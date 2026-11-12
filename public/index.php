<?php
declare(strict_types=1);
ini_set('display_errors','0');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store, private');
session_name('sentinel_session');
session_set_cookie_params(['httponly'=>true,'secure'=>($_SERVER['HTTP_X_FORWARDED_PROTO']??'')==='https'||!empty($_SERVER['HTTPS']),'samesite'=>'Lax']);
session_start();
function h($s):string{return htmlspecialchars((string)$s,ENT_QUOTES|ENT_SUBSTITUTE,'UTF-8');}
function db():PDO{static $db=null;if(!$db){$db=new PDO(getenv('DB_DSN')?:'',getenv('DB_USER')?:'',getenv('DB_PASSWORD')?:'',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,PDO::ATTR_EMULATE_PREPARES=>false]);}return $db;}
function q(string $sql,array $a=[]):PDOStatement{$s=db()->prepare($sql);$s->execute($a);return $s;}
function init():void{
 if(getenv('DEMO_AUTO_SETUP')!=='1')return;
 if(!db()->query("SHOW TABLES LIKE 'roles'")->fetch()){
  $sql=file_get_contents('/var/www/database/schema.sql');
  foreach(explode(';',$sql) as $statement){$statement=trim($statement);if($statement)db()->exec($statement);}
 }
 if((int)q('SELECT COUNT(*) FROM users')->fetchColumn()===0){
  q('INSERT INTO residents(full_name,phone,unit_number) VALUES (?,?,?)',['Demo Resident','0700000000','A-01']);
  $rid=(int)db()->lastInsertId();
  foreach([[1,null,'Demo Administrator','admin@sentinel.demo'],[2,null,'Demo Security Officer','officer@sentinel.demo'],[3,$rid,'Demo Resident','resident@sentinel.demo']] as $u){
   q('INSERT INTO users(role_id,resident_id,full_name,email,password_hash) VALUES (?,?,?,?,?)',[$u[0],$u[1],$u[2],$u[3],password_hash((string)getenv('DEMO_PASSWORD'),PASSWORD_DEFAULT)]);
  }
 }
}
try{init();$ready=(bool)db()->query("SHOW TABLES LIKE 'users'")->fetch();}catch(Throwable $ex){$ready=false;error_log('Sentinel setup: '.$ex->getMessage());}
if(isset($_GET['health'])){header('Content-Type: application/json');http_response_code($ready?200:503);echo json_encode(['status'=>$ready?'ok':'database_unavailable']);exit;}
if(!$ready){http_response_code(503);exit('Application is initializing. Please retry shortly.');}
function csrf():string{return $_SESSION['csrf']??=bin2hex(random_bytes(24));}
function check():void{if(!hash_equals(csrf(),(string)($_POST['csrf']??''))){http_response_code(419);exit('Invalid request token');}}
function who():?array{if(empty($_SESSION['uid']))return null;$u=q('SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?',[$_SESSION['uid']])->fetch();if(!$u||!$u['active']||(int)$u['session_version']!==(int)($_SESSION['sv']??0)){$_SESSION=[];return null;}if($u['role']==='resident'&&!q("SELECT id FROM residents WHERE id=? AND status='active'",[$u['resident_id']])->fetch()){$_SESSION=[];return null;}return $u;}
function go(string $p):never{header('Location: /?page='.$p);exit;}
function role(array $allowed):array{$u=who();if(!$u){go('login');}if(!in_array($u['role'],$allowed,true)){http_response_code(403);exit('Access denied');}return $u;}
function logit(int $id,string $action,string $type='',?int $sid=null):void{q('INSERT INTO audit_logs(actor_id,action,subject_type,subject_id) VALUES (?,?,?,?)',[$id,$action,$type,$sid]);}
$page=(string)($_GET['page']??'dashboard');$u=who();
if($page==='login'&&$_SERVER['REQUEST_METHOD']==='POST'){
 check();$email=strtolower(trim((string)($_POST['email']??'')));$pw=(string)($_POST['password']??'');
 $n=(int)q('SELECT COUNT(*) FROM login_attempts WHERE email=? AND succeeded=0 AND created_at>DATE_SUB(NOW(),INTERVAL 15 MINUTE)',[$email])->fetchColumn();
 $candidate=$n<8?q('SELECT * FROM users WHERE email=? AND active=1',[$email])->fetch():false;
 $valid=$candidate&&password_verify($pw,$candidate['password_hash']);
 if($valid&&(int)$candidate['role_id']===3&&!q("SELECT id FROM residents WHERE id=? AND status='active'",[$candidate['resident_id']])->fetch())$valid=false;
 q('INSERT INTO login_attempts(email,ip_hash,succeeded) VALUES (?,?,?)',[$email,hash('sha256',$_SERVER['REMOTE_ADDR']??''),(int)(bool)$valid]);
 if($valid){q('DELETE FROM login_attempts WHERE email=? AND succeeded=0',[$email]);session_regenerate_id(true);$_SESSION['uid']=$candidate['id'];$_SESSION['sv']=$candidate['session_version'];go('dashboard');}
 $error='Incorrect credentials or too many attempts.';
}
if($page==='logout'&&$_SERVER['REQUEST_METHOD']==='POST'){check();$_SESSION=[];session_regenerate_id(true);go('login');}
if(!$u&&$page!=='login')go('login');
if($u&&$page==='login')go('dashboard');
if($u&&$_SERVER['REQUEST_METHOD']==='POST'){
 check();$action=(string)($_POST['action']??'');
 try{
  if($action==='resident_add'){role(['administrator']);$name=trim((string)($_POST['name']??''));if(!$name||mb_strlen($name)>120)throw new Exception('Invalid resident name');q('INSERT INTO residents(full_name,phone,unit_number) VALUES (?,?,?)',[$name,substr(trim((string)($_POST['phone']??'')),0,30),substr(trim((string)($_POST['unit']??'')),0,40)]);logit((int)$u['id'],'resident.create','resident',(int)db()->lastInsertId());go('residents');}
  if($action==='resident_edit'){role(['administrator']);q('UPDATE residents SET full_name=?,phone=?,unit_number=? WHERE id=?',[substr(trim((string)$_POST['name']),0,120),substr(trim((string)$_POST['phone']),0,30),substr(trim((string)$_POST['unit']),0,40),(int)$_POST['id']]);go('residents');}
  if($action==='resident_toggle'){role(['administrator']);q("UPDATE residents SET status=IF(status='active','inactive','active') WHERE id=?",[(int)$_POST['id']]);go('residents');}
  if($action==='visit_add'){role(['administrator','security_officer']);$host=(int)($_POST['host']??0);if(!q("SELECT id FROM residents WHERE id=? AND status='active'",[$host])->fetch())throw new Exception('Choose an active resident');$name=trim((string)($_POST['name']??''));$purpose=trim((string)($_POST['purpose']??''));if(!$name||!$purpose)throw new Exception('Visitor and purpose required');q('INSERT INTO visits(visitor_name,host_resident_id,purpose,recorded_by) VALUES (?,?,?,?)',[substr($name,0,120),$host,substr($purpose,0,250),$u['id']]);logit((int)$u['id'],'visit.checkin');go('visitors');}
  if($action==='visit_out'){role(['administrator','security_officer']);q('UPDATE visits SET time_out=NOW() WHERE id=? AND time_out IS NULL',[(int)$_POST['id']]);go('visitors');}
  if($action==='incident_add'){$title=trim((string)($_POST['title']??''));$desc=trim((string)($_POST['description']??''));if(!$title||!$desc)throw new Exception('Title and description required');q('INSERT INTO incidents(title,description,category,reported_by) VALUES (?,?,?,?)',[substr($title,0,160),substr($desc,0,10000),substr(trim((string)($_POST['category']??'General')),0,60),$u['id']]);go('incidents');}
  if($action==='incident_status'){role(['administrator','security_officer']);$status=(string)$_POST['status'];if(!in_array($status,['open','in_progress','resolved'],true))throw new Exception('Invalid status');q('UPDATE incidents SET status=? WHERE id=?',[$status,(int)$_POST['id']]);go('incidents');}
  if($action==='notice_add'){role(['administrator']);$title=trim((string)$_POST['title']);$body=trim((string)$_POST['body']);if(!$title||!$body)throw new Exception('Notice fields required');q('INSERT INTO notices(title,body,created_by) VALUES (?,?,?)',[substr($title,0,160),substr($body,0,10000),$u['id']]);go('notices');}
  if($action==='notice_toggle'){role(['administrator']);q('UPDATE notices SET active=NOT active WHERE id=?',[(int)$_POST['id']]);go('notices');}
  if($action==='user_add'){role(['administrator']);$r=(int)$_POST['role_id'];$rid=($_POST['resident_id']??'')!==''?(int)$_POST['resident_id']:null;$pw=(string)$_POST['password'];if(!in_array($r,[1,2,3],true)||($r===3)!==($rid!==null)||strlen($pw)<12||!filter_var($_POST['email'],FILTER_VALIDATE_EMAIL))throw new Exception('Check role, resident link, email and password');q('INSERT INTO users(role_id,resident_id,full_name,email,password_hash) VALUES (?,?,?,?,?)',[$r,$rid,substr(trim((string)$_POST['name']),0,120),strtolower(trim((string)$_POST['email'])),password_hash($pw,PASSWORD_DEFAULT)]);go('users');}
  if($action==='user_toggle'){role(['administrator']);if((int)$_POST['id']===(int)$u['id'])throw new Exception('Cannot disable own account');q('UPDATE users SET active=NOT active,session_version=session_version+1 WHERE id=?',[(int)$_POST['id']]);go('users');}
  if($action==='password_change'){$old=(string)$_POST['old'];$pw=(string)$_POST['new'];if(!password_verify($old,$u['password_hash'])||strlen($pw)<12)throw new Exception('Invalid current or new password');q('UPDATE users SET password_hash=?,session_version=session_version+1 WHERE id=?',[password_hash($pw,PASSWORD_DEFAULT),$u['id']]);$_SESSION['sv']++;go('account');}
 }catch(Throwable $ex){$error=$ex->getMessage();}
}
if($page==='reports'){$u=role(['administrator','security_officer']);if(isset($_GET['csv'])){$type=(string)$_GET['csv'];$queries=['residents'=>'SELECT id,full_name,phone,unit_number,status,created_at FROM residents','visitors'=>'SELECT id,visitor_name,host_resident_id,purpose,time_in,time_out FROM visits','incidents'=>'SELECT id,title,category,status,created_at FROM incidents'];if(!isset($queries[$type])){http_response_code(400);exit('Invalid report');}header('Content-Type: text/csv');header('Content-Disposition: attachment; filename="'.$type.'.csv"');$fp=fopen('php://output','w');$rows=q($queries[$type]);$first=$rows->fetch();if($first){fputcsv($fp,array_keys($first));fputcsv($fp,$first);while($row=$rows->fetch())fputcsv($fp,$row);}exit;}}
function formStart(string $action):string{return '<form method="post" class="form"><input type="hidden" name="csrf" value="'.h(csrf()).'"><input type="hidden" name="action" value="'.h($action).'">';}
function field(string $name,string $label,string $type='text',string $value=''):string{return '<label>'.h($label).'<input name="'.h($name).'" type="'.h($type).'" value="'.h($value).'" required></label>';}
function button(string $label):string{return '<button type="submit">'.h($label).'</button></form>';}
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel Neighborhood</title><link rel="stylesheet" href="/assets/style.css"></head><body>
<?php if(!$u): ?><main class="login"><section class="hero"><div class="brand">◈ SENTINEL <span>NEIGHBORHOOD</span></div><h1>A safer community starts with better coordination.</h1><p>Manage visitors, report incidents and keep your neighborhood informed.</p></section><section class="loginbox"><div class="eyebrow">SECURE ACCESS</div><h2>Welcome back</h2><p>Sign in to your neighborhood workspace.</p><?php if(isset($error)):?><p class="error"><?=h($error)?></p><?php endif;?><?=formStart('login')?><?=field('email','Email address','email')?><?=field('password','Password','password')?><?=button('Sign in')?></section></main>
<?php else: ?><div class="layout"><aside><div class="brand">◈ SENTINEL <span>NEIGHBORHOOD</span></div><p class="muted"><?=h($u['role'])?></p><nav><?php foreach(['dashboard'=>'Overview','visitors'=>'Visitors','incidents'=>'Incidents','notices'=>'Announcements','account'=>'My account'] as $key=>$label):?><a class="<?=$page===$key?'selected':''?>" href="/?page=<?=$key?>"><?=h($label)?></a><?php endforeach;?><?php if($u['role']==='administrator'):?><a href="/?page=residents">Residents</a><a href="/?page=users">Users</a><?php endif;?><?php if($u['role']!=='resident'):?><a href="/?page=reports">Reports</a><?php endif;?></nav><?=formStart('logout')?><button>Sign out</button></form></aside><main class="content"><header><div><div class="eyebrow">NEIGHBORHOOD SECURITY MANAGEMENT</div><h1><?=h(ucfirst($page))?></h1></div><span class="pill"><?=h($u['full_name'])?></span></header><?php if(isset($error)):?><p class="error"><?=h($error)?></p><?php endif;?>
<?php
if($page==='dashboard'){
 $counts=['Residents'=>(int)q("SELECT COUNT(*) FROM residents WHERE status='active'")->fetchColumn(),'Visitors on site'=>(int)q("SELECT COUNT(*) FROM visits WHERE time_out IS NULL".($u['role']==='resident'?' AND host_resident_id='.(int)$u['resident_id']:''))->fetchColumn(),'Open incidents'=>(int)q("SELECT COUNT(*) FROM incidents WHERE status!='resolved'".($u['role']==='resident'?' AND reported_by='.(int)$u['id']:''))->fetchColumn()];
 echo '<div class="stats">';foreach($counts as $name=>$value)echo '<article><span>'.h($name).'</span><strong>'.$value.'</strong></article>';echo '</div><section class="panel"><h2>Latest announcements</h2>';
 foreach(q('SELECT title,body,created_at FROM notices WHERE active=1 ORDER BY id DESC LIMIT 5')->fetchAll() as $n)echo '<div class="entry"><strong>'.h($n['title']).'</strong><p>'.h($n['body']).'</p></div>';echo '</section>';
}
if($page==='residents'){
 role(['administrator']);echo '<section class="panel"><h2>Add resident</h2>'.formStart('resident_add').field('name','Full name').field('phone','Phone').field('unit','House / unit').button('Register resident').'</section>';
 foreach(q('SELECT * FROM residents ORDER BY id DESC LIMIT 100')->fetchAll() as $r){echo '<section class="panel">'.formStart('resident_edit').'<input type="hidden" name="id" value="'.(int)$r['id'].'">'.field('name','Name','text',$r['full_name']).field('phone','Phone','text',$r['phone']).field('unit','House / unit','text',$r['unit_number']).button('Save changes').'<p>Status: '.h($r['status']).'</p>'.formStart('resident_toggle').'<input type="hidden" name="id" value="'.(int)$r['id'].'">'.button('Activate / deactivate').'</section>';}
}
if($page==='visitors'){
 if($u['role']!=='resident'){echo '<section class="panel"><h2>Visitor check-in</h2>'.formStart('visit_add').field('name','Visitor name').field('purpose','Purpose').'<label>Host resident<select name="host" required>';foreach(q("SELECT id,full_name,unit_number FROM residents WHERE status='active' ORDER BY full_name")->fetchAll() as $r)echo '<option value="'.$r['id'].'">'.h($r['full_name'].' — '.$r['unit_number']).'</option>';echo '</select></label>'.button('Check in visitor').'</section>';}
 $sql='SELECT v.*,r.full_name host FROM visits v JOIN residents r ON r.id=v.host_resident_id';$args=[];if($u['role']==='resident'){$sql.=' WHERE v.host_resident_id=?';$args[]=$u['resident_id'];}$sql.=' ORDER BY v.id DESC LIMIT 100';
 echo '<section class="panel"><h2>Visitor history</h2>';foreach(q($sql,$args)->fetchAll() as $v){echo '<div class="entry"><strong>'.h($v['visitor_name']).'</strong><p>Host: '.h($v['host']).' · '.h($v['purpose']).'<br>In: '.h($v['time_in']).' · Out: '.h($v['time_out']??'Still on site').'</p>';if(!$v['time_out']&&$u['role']!=='resident')echo formStart('visit_out').'<input type="hidden" name="id" value="'.$v['id'].'">'.button('Check out');echo '</div>';}echo '</section>';
}
if($page==='incidents'){
 echo '<section class="panel"><h2>Report an incident</h2>'.formStart('incident_add').field('title','Title').field('category','Category').'<label>Description<textarea name="description" required></textarea></label>'.button('Submit incident').'</section>';
 $sql='SELECT i.*,u.full_name reporter FROM incidents i JOIN users u ON u.id=i.reported_by';$args=[];if($u['role']==='resident'){$sql.=' WHERE i.reported_by=?';$args[]=$u['id'];}$sql.=' ORDER BY i.id DESC LIMIT 100';echo '<section class="panel"><h2>Incident records</h2>';foreach(q($sql,$args)->fetchAll() as $i){echo '<div class="entry"><strong>'.h($i['title']).'</strong><p>'.h($i['description']).'</p><small>'.h($i['category'].' · '.$i['status'].' · '.$i['reporter']).'</small>';if($u['role']!=='resident')echo formStart('incident_status').'<input type="hidden" name="id" value="'.$i['id'].'"><select name="status"><option value="open">Open</option><option value="in_progress">In progress</option><option value="resolved">Resolved</option></select>'.button('Update status');echo '</div>';}echo '</section>';
}
if($page==='notices'){
 if($u['role']==='administrator')echo '<section class="panel"><h2>Publish announcement</h2>'.formStart('notice_add').field('title','Title').'<label>Message<textarea name="body" required></textarea></label>'.button('Publish').'</section>';
 $sql='SELECT * FROM notices'.($u['role']==='administrator'?'':' WHERE active=1').' ORDER BY id DESC LIMIT 100';echo '<section class="panel"><h2>Community notices</h2>';foreach(q($sql)->fetchAll() as $n){echo '<div class="entry"><strong>'.h($n['title']).'</strong><p>'.h($n['body']).'</p><small>'.($n['active']?'Active':'Hidden').'</small>';if($u['role']==='administrator')echo formStart('notice_toggle').'<input type="hidden" name="id" value="'.$n['id'].'">'.button('Toggle visibility');echo '</div>';}echo '</section>';
}
if($page==='users'){
 role(['administrator']);echo '<section class="panel"><h2>Create user</h2>'.formStart('user_add').field('name','Full name').field('email','Email','email').field('password','Temporary password (12+ characters)','password').'<label>Role<select name="role_id"><option value="1">Administrator</option><option value="2">Security officer</option><option value="3">Resident</option></select></label><label>Linked resident (required for resident role)<select name="resident_id"><option value="">None</option>';foreach(q("SELECT id,full_name FROM residents WHERE status='active'")->fetchAll() as $r)echo '<option value="'.$r['id'].'">'.h($r['full_name']).'</option>';echo '</select></label>'.button('Create account').'</section><section class="panel"><h2>Accounts</h2>';foreach(q('SELECT id,full_name,email,active FROM users ORDER BY id DESC')->fetchAll() as $a){echo '<div class="entry"><strong>'.h($a['full_name']).'</strong><p>'.h($a['email']).' · '.($a['active']?'Active':'Disabled').'</p>';if($a['id']!=$u['id'])echo formStart('user_toggle').'<input type="hidden" name="id" value="'.$a['id'].'">'.button('Toggle access');echo '</div>';}echo '</section>';
}
if($page==='reports'){role(['administrator','security_officer']);echo '<section class="panel"><h2>Export reports</h2><p>Download current system records as CSV.</p>';foreach(['residents','visitors','incidents'] as $type)echo '<p><a href="/?page=reports&amp;csv='.$type.'">Download '.h(ucfirst($type)).' CSV</a></p>';echo '</section>';}
if($page==='account')echo '<section class="panel"><h2>Change password</h2>'.formStart('password_change').field('old','Current password','password').field('new','New password (12+ characters)','password').button('Change password').'</section>';
?></main></div><?php endif;?></body></html>
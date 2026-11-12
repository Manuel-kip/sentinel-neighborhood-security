<?php
declare(strict_types=1);
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
$ok=false;$message='Database not configured';
try {
 $dsn=getenv('DB_DSN');
 if($dsn){$db=new PDO($dsn,getenv('DB_USER')?:'',getenv('DB_PASSWORD')?:'',[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_TIMEOUT=>5]);$db->query('SELECT 1');$ok=true;$message='Database connected';}
} catch(Throwable $e){$message='Database connection unavailable';}
if(($_GET['health']??'')==='1'){http_response_code($ok?200:503);header('Content-Type: application/json');echo json_encode(['application'=>'sentinel-neighborhood','database'=>$ok?'connected':'unavailable']);exit;}
?><!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sentinel Neighborhood — Deployment Verification</title><style>body{font-family:system-ui,Arial;background:#0b1528;color:#edf4ff;min-height:100vh;display:grid;place-items:center;margin:0;padding:18px}.card{max-width:560px;padding:38px;border:1px solid #30465c;border-radius:22px;background:#14243b}h1{font-size:30px;margin:0 0 8px}p{line-height:1.65;color:#bed0e1}.tag{display:inline-block;padding:8px 12px;border-radius:9px;background:#243b4e;color:#a8e7d2;font-weight:700}a{color:#70dfc1}</style></head><body><main class="card"><p class="tag">Independent deployment verification</p><h1>Sentinel Neighborhood</h1><p>This is the isolated hosting verification page. The complete neighborhood security application is not published here yet.</p><p>MySQL status: <strong><?=htmlspecialchars($message,ENT_QUOTES)?></strong></p><p><a href="?health=1">Check database health</a></p></main></body></html>
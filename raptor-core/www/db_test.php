<?php
header('Content-Type: application/json; charset=utf-8');
try {
    $pdo = new PDO('mysql:host=127.0.0.1;dbname=raptor_db;charset=utf8mb4',
        'raptor_app', 'CHANGE_ME_RAPTOR_APP_PASS', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['component'])) {
        $ins = $pdo->prepare('INSERT INTO raptor_status (component) VALUES (:c)');
        $ins->execute([':c' => substr(trim($_POST['component']), 0, 60)]);
    }
    $st = $pdo->query('SELECT id, component, updated_at FROM raptor_status ORDER BY id DESC LIMIT 5');
    echo json_encode(['status' => 'ok', 'method' => $_SERVER['REQUEST_METHOD'],
        'rows' => $st->fetchAll(PDO::FETCH_ASSOC)]) . "\n";
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'detail' => $e->getMessage()]) . "\n";
}

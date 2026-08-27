# -*- coding: utf-8 -*-
"""Énoncé A — Examen blanc Linux Essentials 010-160 — Niger Certify (propriétaire)."""

COMMON = {
    "header_line": "Examen blanc Linux Essentials 010-160  ·  Document propriétaire",
    "referentiel": "LPI Linux Essentials 010-160 v1.6",
    "blueprint_title": "Répartition (objectifs LPI Linux Essentials v1.6)",
    "blueprint_text": (
        "Communauté Linux et carrière open source 17,5 %  ·  "
        "S'orienter sur un système Linux 22,5 %  ·  "
        "La puissance de la ligne de commande 22,5 %  ·  "
        "Le système d'exploitation Linux 20 %  ·  "
        "Sécurité et permissions 17,5 %."
    ),
    "scoring_notes": [
        "Partie A (Q 1–28) : une seule bonne réponse — 1 point.",
        "Partie B (Q 29–34) : plusieurs bonnes réponses — 2 points, tout ou rien.",
        "Partie C (Q 35–40) : scénarios / sorties de commandes — 2 points.",
        "Total : 52 points. Seuil indicatif « prêt LPI » : 67 % (35/52).",
        "Mini-lab papier : hors barème principal (bonus formateur +10 pts max si activé).",
        "Écrire lisiblement. Les ratures illisibles sont nulles.",
    ],
    "pdf_subject": "Examen blanc Linux Essentials 010-160 v1.6 — Niger Certify",
    "pdf_keywords": "Linux Essentials, LPI, 010-160, Niger Certify, examen blanc, propriétaire",
    "corrige_code": "NC-LE-BLANC-CORRIGE-2026",
    "corrige_subtitle": "LPI Linux Essentials 010-160 v1.6  ·  CONFIDENTIEL FORMATEUR",
    "interpretation": (
        "≥ 90 % : prêt examen officiel LPI.  80–89 % : blanc réussi, revoir 1–2 thèmes.  "
        "67–79 % : seuil minimal, renforcer scripts, permissions et chemins.  "
        "&lt; 67 % : ne pas planifier le voucher 010-160."
    ),
}

EXAM_A = {
    **COMMON,
    "version": "A",
    "code": "NC-LE-BLANC-A-2026",
    "title": "Examen blanc Linux Essentials",
    "subtitle": "Linux Professional Institute  ·  Exam 010-160  ·  objectifs v1.6",
    "duration": "60 minutes",
    "n_questions": 40,
    "bareme": "52 points (A 28 + B 12 + C 12)",
    "seuil": "67 %  ≈  35 / 52",
    "parts": [
        {
            "title": "Partie A — QCM (une seule bonne réponse)",
            "intro": "Questions 1 à 28. Cochez une seule case. Barème : 1 point par question.",
            "questions": [
                {
                    "n": 1,
                    "points": 1,
                    "stem": "Quelle famille de distributions utilise principalement des paquets <font face='NC-Mono'>RPM</font> (yum, dnf ou zypper) ?",
                    "choices": [
                        ("A", "Debian, Ubuntu et Linux Mint"),
                        ("B", "Red Hat, Fedora, CentOS Stream et openSUSE"),
                        ("C", "Android uniquement"),
                        ("D", "Microsoft Windows Server"),
                    ],
                    "answer": "B",
                    "explain": "RPM = famille Red Hat / SUSE. Debian/Ubuntu = .deb + apt.",
                },
                {
                    "n": 2,
                    "points": 1,
                    "stem": "Android et Raspberry Pi OS illustrent surtout :",
                    "choices": [
                        ("A", "Linux embarqué / mobile (et carte monocarte)"),
                        ("B", "Des hyperviseurs de type 1 uniquement"),
                        ("C", "Des forks propriétaires de Windows"),
                        ("D", "Le remplacement de GNU par un noyau BSD"),
                    ],
                    "answer": "A",
                    "explain": "Objectif 1.1 : embedded (Android, Raspberry Pi / Raspbian).",
                },
                {
                    "n": 3,
                    "points": 1,
                    "stem": "Quel logiciel open source est l'équivalent de bureau le plus courant de Microsoft Office ?",
                    "choices": [
                        ("A", "GIMP"),
                        ("B", "LibreOffice"),
                        ("C", "NGINX"),
                        ("D", "MariaDB"),
                    ],
                    "answer": "B",
                    "explain": "LibreOffice (suite bureautique). GIMP = retouche ; NGINX/MariaDB = serveur.",
                },
                {
                    "n": 4,
                    "points": 1,
                    "stem": "Sur Ubuntu, quelle commande installe le paquet nginx depuis les dépôts ?",
                    "choices": [
                        ("A", "rpm -i nginx"),
                        ("B", "yum install nginx"),
                        ("C", "sudo apt-get install nginx"),
                        ("D", "dpkg --purge nginx"),
                    ],
                    "answer": "C",
                    "explain": "Debian/Ubuntu : apt-get / apt. rpm/yum = famille Red Hat.",
                },
                {
                    "n": 5,
                    "points": 1,
                    "stem": "La licence GNU GPL est principalement :",
                    "choices": [
                        ("A", "Permissive, comme la BSD (dérivés propriétaires autorisés sans partager le code)."),
                        ("B", "Copyleft : les œuvres dérivées doivent rester sous GPL."),
                        ("C", "Un brevet matériel déposé par Linus Torvalds."),
                        ("D", "Une licence Creative Commons Photo uniquement."),
                    ],
                    "answer": "B",
                    "explain": "GPL = copyleft. BSD/MIT = permissives.",
                },
                {
                    "n": 6,
                    "points": 1,
                    "stem": "La variable d'environnement <font face='NC-Mono'>PATH</font> sert à :",
                    "choices": [
                        ("A", "Lister les processus en cours."),
                        ("B", "Indiquer les répertoires où le shell cherche les commandes."),
                        ("C", "Définir le serveur DNS."),
                        ("D", "Monter automatiquement /home."),
                    ],
                    "answer": "B",
                    "explain": "Le shell parcourt PATH pour résoudre ls, grep, etc.",
                },
                {
                    "n": 7,
                    "points": 1,
                    "stem": "Quelle commande affiche le texte littéral <font face='NC-Mono'>$HOME</font> (sans expansion) ?",
                    "choices": [
                        ("A", "echo $HOME"),
                        ("B", "echo \"$HOME\""),
                        ("C", "echo '$HOME'"),
                        ("D", "echo `$HOME`"),
                    ],
                    "answer": "C",
                    "explain": "Guillemets simples : pas d'expansion. Doubles et sans quotes : expansion.",
                },
                {
                    "n": 8,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>man ls</font> affiche généralement une page de quelle section du manuel ?",
                    "choices": [
                        ("A", "Section 5 (formats de fichiers de config)"),
                        ("B", "Section 1 (commandes utilisateur)"),
                        ("C", "Section 8 uniquement (administration)"),
                        ("D", "Section 9 (routines interne du noyau)"),
                    ],
                    "answer": "B",
                    "explain": "man 1 = commandes ; man 5 = formats ; man 8 = admin.",
                },
                {
                    "n": 9,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>ls -a</font> dans un répertoire affiche :",
                    "choices": [
                        ("A", "Uniquement les sous-répertoires."),
                        ("B", "Tous les fichiers, y compris ceux dont le nom commence par un point."),
                        ("C", "Les numéros d'inode seulement."),
                        ("D", "Les processus de l'utilisateur."),
                    ],
                    "answer": "B",
                    "explain": "-a = all, y compris .bashrc, . et ..",
                },
                {
                    "n": 10,
                    "points": 1,
                    "stem": "Depuis <font face='NC-Mono'>/home/awa/docs</font>, la commande <font face='NC-Mono'>cd ..</font> mène à :",
                    "choices": [
                        ("A", "/"),
                        ("B", "/home/awa"),
                        ("C", "/home"),
                        ("D", "/docs"),
                    ],
                    "answer": "B",
                    "explain": ".. = répertoire parent.",
                },
                {
                    "n": 11,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>rmdir projet</font> échoue le plus souvent si :",
                    "choices": [
                        ("A", "projet est un fichier vide créé par touch."),
                        ("B", "projet est un répertoire qui contient encore des fichiers."),
                        ("C", "vous êtes connecté en root."),
                        ("D", "le sticky bit est absent sur /home."),
                    ],
                    "answer": "B",
                    "explain": "rmdir n'efface que des répertoires vides. Sinon rm -r.",
                },
                {
                    "n": 12,
                    "points": 1,
                    "stem": "Quelle commande crée un fichier vide <font face='NC-Mono'>notes.txt</font> s'il n'existe pas (ou met à jour son horodatage) ?",
                    "choices": [
                        ("A", "mkdir notes.txt"),
                        ("B", "touch notes.txt"),
                        ("C", "rm notes.txt"),
                        ("D", "ln notes.txt"),
                    ],
                    "answer": "B",
                    "explain": "touch = créer vide / actualiser mtime.",
                },
                {
                    "n": 13,
                    "points": 1,
                    "stem": "La commande <font face='NC-Mono'>tar czf backup.tar.gz dossier/</font> :",
                    "choices": [
                        ("A", "Extrait une archive xz."),
                        ("B", "Crée une archive tar compressée avec gzip."),
                        ("C", "Convertit le dossier en zip Windows uniquement."),
                        ("D", "Monte un système de fichiers."),
                    ],
                    "answer": "B",
                    "explain": "c = create, z = gzip, f = fichier.",
                },
                {
                    "n": 14,
                    "points": 1,
                    "stem": "Quel outil produit typiquement une extension <font face='NC-Mono'>.xz</font> ?",
                    "choices": [
                        ("A", "gzip"),
                        ("B", "bzip2"),
                        ("C", "xz"),
                        ("D", "zip sans compression"),
                    ],
                    "answer": "C",
                    "explain": ".gz = gzip ; .bz2 = bzip2 ; .xz = xz.",
                },
                {
                    "n": 15,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>grep -i error /var/log/syslog</font> :",
                    "choices": [
                        ("A", "Recherche sensible à la casse uniquement « error » minuscule."),
                        ("B", "Recherche « error » sans tenir compte de la casse."),
                        ("C", "Supprime les lignes contenant error."),
                        ("D", "Trie le fichier par date."),
                    ],
                    "answer": "B",
                    "explain": "-i = ignore case.",
                },
                {
                    "n": 16,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>ls /etc &gt; liste.txt</font> :",
                    "choices": [
                        ("A", "Ajoute la sortie à la fin de liste.txt (append)."),
                        ("B", "Écrase ou crée liste.txt avec la sortie standard de ls."),
                        ("C", "Redirige uniquement stderr."),
                        ("D", "Crée un tube vers un autre processus."),
                    ],
                    "answer": "B",
                    "explain": "&gt; écrase ; &gt;&gt; ajoute ; | = pipe.",
                },
                {
                    "n": 17,
                    "points": 1,
                    "stem": "La première ligne <font face='NC-Mono'>#!/bin/bash</font> d'un script :",
                    "choices": [
                        ("A", "Est un commentaire toujours ignoré par le noyau."),
                        ("B", "Indique l'interpréteur à utiliser (shebang)."),
                        ("C", "Compile le fichier en binaire C."),
                        ("D", "Active automatiquement sudo."),
                    ],
                    "answer": "B",
                    "explain": "Shebang #! = interpréteur.",
                },
                {
                    "n": 18,
                    "points": 1,
                    "stem": "Dans un script Bash, <font face='NC-Mono'>$1</font> désigne :",
                    "choices": [
                        ("A", "Le code de retour de la dernière commande."),
                        ("B", "Le premier argument passé au script."),
                        ("C", "Le PID du script."),
                        ("D", "La variable HOME."),
                    ],
                    "answer": "B",
                    "explain": "$1, $2… arguments ; $? = exit status ; $$ = PID.",
                },
                {
                    "n": 19,
                    "points": 1,
                    "stem": "Les fichiers de configuration système se trouvent typiquement dans :",
                    "choices": [
                        ("A", "/var/log"),
                        ("B", "/etc"),
                        ("C", "/proc"),
                        ("D", "/tmp"),
                    ],
                    "answer": "B",
                    "explain": "/etc = config ; /var/log = journaux ; /proc = virtuel noyau.",
                },
                {
                    "n": 20,
                    "points": 1,
                    "stem": "La commande <font face='NC-Mono'>free</font> affiche :",
                    "choices": [
                        ("A", "L'espace disque des partitions."),
                        ("B", "L'utilisation de la mémoire RAM et du swap."),
                        ("C", "La table de routage."),
                        ("D", "Les utilisateurs connectés."),
                    ],
                    "answer": "B",
                    "explain": "free = mémoire. df = disque. who/w = sessions.",
                },
                {
                    "n": 21,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>/dev/sda</font> désigne généralement :",
                    "choices": [
                        ("A", "Un processus en mémoire."),
                        ("B", "Le premier disque (SATA/SCSI/SSD) vu par Linux."),
                        ("C", "Un fichier de journal syslog."),
                        ("D", "La mémoire RAM."),
                    ],
                    "answer": "B",
                    "explain": "Nœuds périphériques /dev/sd* ; partitions sda1, sda2…",
                },
                {
                    "n": 22,
                    "points": 1,
                    "stem": "Le fichier <font face='NC-Mono'>/etc/resolv.conf</font> contient surtout :",
                    "choices": [
                        ("A", "La route par défaut."),
                        ("B", "Les serveurs DNS (nameserver)."),
                        ("C", "Les hachages de mots de passe."),
                        ("D", "Les modules du noyau."),
                    ],
                    "answer": "B",
                    "explain": "Client DNS. Routes = ip route ; mots de passe = /etc/shadow.",
                },
                {
                    "n": 23,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>ping 8.8.8.8</font> teste principalement :",
                    "choices": [
                        ("A", "La résolution DNS d'un nom."),
                        ("B", "La connectivité IP (ICMP) vers l'hôte."),
                        ("C", "L'accès SSH."),
                        ("D", "Le sticky bit de /tmp."),
                    ],
                    "answer": "B",
                    "explain": "ping = ICMP. DNS = host / getent / ping d'un nom.",
                },
                {
                    "n": 24,
                    "points": 1,
                    "stem": "L'utilisateur <b>root</b> a pour UID typique :",
                    "choices": [
                        ("A", "1000"),
                        ("B", "0"),
                        ("C", "65534"),
                        ("D", "1 (daemon)"),
                    ],
                    "answer": "B",
                    "explain": "UID 0 = root. 1000 = premier utilisateur « humain » fréquent.",
                },
                {
                    "n": 25,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>chmod 644 fichier.txt</font> donne les permissions :",
                    "choices": [
                        ("A", "rwxrwxrwx"),
                        ("B", "rw-r--r--"),
                        ("C", "rwxr-xr-x"),
                        ("D", "rw-------"),
                    ],
                    "answer": "B",
                    "explain": "6=rw-, 4=r--, 4=r--.",
                },
                {
                    "n": 26,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>sudo apt-get update</font> sert à :",
                    "choices": [
                        ("A", "Exécuter la commande avec les privilèges d'un autre utilisateur (souvent root)."),
                        ("B", "Changer définitivement d'identité sans mot de passe, comme su -."),
                        ("C", "Compresser le cache apt."),
                        ("D", "Désactiver le pare-feu."),
                    ],
                    "answer": "A",
                    "explain": "sudo = exécution privilégiée ponctuelle. su = changer d'utilisateur.",
                },
                {
                    "n": 27,
                    "points": 1,
                    "stem": "Le sticky bit (t) sur <font face='NC-Mono'>/tmp</font> signifie :",
                    "choices": [
                        ("A", "Tout le monde peut supprimer n'importe quel fichier du répertoire."),
                        ("B", "Seul le propriétaire du fichier (ou root) peut le supprimer, malgré un écriture mondiale."),
                        ("C", "Plus aucune écriture n'est possible."),
                        ("D", "Tous les fichiers sont des liens durs."),
                    ],
                    "answer": "B",
                    "explain": "Sticky bit = protection contre la suppression croisée dans /tmp.",
                },
                {
                    "n": 28,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>ln -s /etc/hosts ~/h</font> :",
                    "choices": [
                        ("A", "Crée un lien dur (même inode)."),
                        ("B", "Crée un lien symbolique nommé h vers /etc/hosts."),
                        ("C", "Copie le contenu de hosts dans h."),
                        ("D", "Formate la partition /home."),
                    ],
                    "answer": "B",
                    "explain": "ln -s = symlink. ln sans -s = hard link.",
                },
            ],
        },
        {
            "title": "Partie B — Plusieurs réponses",
            "intro": "Questions 29 à 34. Toutes les bonnes cases doivent être cochées, aucune mauvaise. Barème : 2 points, tout ou rien.",
            "questions": [
                {
                    "n": 29,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations correctes sur le logiciel libre / open source.",
                    "choices": [
                        ("A", "La FSF promeut le logiciel libre et le copyleft (ex. GPL)."),
                        ("B", "L'OSI définit des licences open source (dont des licences permissives)."),
                        ("C", "FOSS interdit toute utilisation en entreprise."),
                        ("D", "Une licence BSD oblige toujours à republier les dérivés sous GPL."),
                        ("E", "Android n'a aucun lien avec le noyau Linux."),
                    ],
                    "answer": "A, B",
                    "explain": "FSF + OSI. BSD = permissive. FOSS est largement utilisé en entreprise.",
                },
                {
                    "n": 30,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations correctes sur les chemins et le home.",
                    "choices": [
                        ("A", "Le tilde ~ désigne le répertoire personnel de l'utilisateur."),
                        ("B", "Un chemin commençant par / est un chemin absolu."),
                        ("C", ". est le répertoire parent."),
                        ("D", "Les noms de fichiers Linux sont insensibles à la casse, comme NTFS par défaut."),
                        ("E", "cd sans argument mène toujours à /root, même pour un utilisateur standard."),
                    ],
                    "answer": "A, B",
                    "explain": ". = courant, .. = parent. Linux est sensible à la casse. cd = $HOME.",
                },
                {
                    "n": 31,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> outils / notions pour extraire ou filtrer du texte.",
                    "choices": [
                        ("A", "grep"),
                        ("B", "Le tube | (pipe) relie stdout d'une commande à stdin de la suivante"),
                        ("C", "chmod"),
                        ("D", "useradd"),
                        ("E", "fdisk"),
                    ],
                    "answer": "A, B",
                    "explain": "Objectif 3.2 : grep, pipes, redirection, cut, head, wc…",
                },
                {
                    "n": 32,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> éditeurs de texte en ligne de commande dont le candidat Linux Essentials doit avoir conscience.",
                    "choices": [
                        ("A", "nano"),
                        ("B", "vi / vim"),
                        ("C", "Microsoft Word en ligne de commande native Linux"),
                        ("D", "Adobe InDesign"),
                        ("E", "PowerPoint"),
                    ],
                    "answer": "A, B",
                    "explain": "Objectif 3.3 : awareness of vi and nano.",
                },
                {
                    "n": 33,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> emplacements « virtuels » exposés par le noyau.",
                    "choices": [
                        ("A", "/proc"),
                        ("B", "/sys"),
                        ("C", "/home"),
                        ("D", "/var/log/syslog (fichier journal classique, pas un fs virtuel noyau)"),
                        ("E", "/etc/passwd"),
                    ],
                    "answer": "A, B",
                    "explain": "/proc et /sys (et /dev) = interfaces noyau. /home et /etc = disque réel.",
                },
                {
                    "n": 34,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations correctes sur les comptes.",
                    "choices": [
                        ("A", "/etc/passwd liste les comptes (shell, UID, home) et est lisible."),
                        ("B", "/etc/shadow contient les hachages de mots de passe, réservé à root."),
                        ("C", "Tous les UID &gt; 0 sont des comptes root."),
                        ("D", "Les comptes système (daemon) ont toujours UID 0."),
                        ("E", "groupadd crée un utilisateur interactif avec home."),
                    ],
                    "answer": "A, B",
                    "explain": "passwd vs shadow. Comptes système : UID bas, pas de login interactif.",
                },
            ],
        },
        {
            "title": "Partie C — Scénarios et sorties de commandes",
            "intro": "Questions 35 à 40. Lisez la sortie avant de répondre. Barème : 2 points par question.",
            "questions": [
                {
                    "n": 35,
                    "points": 2,
                    "stem": "HOME=/home/awa. Quelle est la sortie de la ligne suivante ?",
                    "code": "echo \"$HOME\" ; echo '$HOME'",
                    "choices": [
                        ("A", "/home/awa deux fois"),
                        ("B", "/home/awa puis $HOME"),
                        ("C", "$HOME puis /home/awa"),
                        ("D", "Deux lignes vides"),
                    ],
                    "answer": "B",
                    "explain": "Doubles quotes : expansion. Simples : littéral.",
                },
                {
                    "n": 36,
                    "points": 2,
                    "stem": "D'après cette ligne <font face='NC-Mono'>ls -l</font>, quelles permissions pour le groupe ?",
                    "code": "-rwxr-x--x 1 awa staff 120 Mar 3 10:00 backup.sh",
                    "choices": [
                        ("A", "rwx (tout)"),
                        ("B", "r-x (lecture + exécution)"),
                        ("C", "--x (exécution seule)"),
                        ("D", "--- (rien)"),
                    ],
                    "answer": "B",
                    "explain": "U=rwx G=r-x O=--x. Groupe = 2e triplet.",
                },
                {
                    "n": 37,
                    "points": 2,
                    "stem": "Quelle est la sortie de ce script ?",
                    "code": "#!/bin/bash\nfor n in 1 2 3; do\n  echo -n \"$n \"\ndone\necho",
                    "choices": [
                        ("A", "1 2 3"),
                        ("B", "123 sans espaces ni retour"),
                        ("C", "n n n"),
                        ("D", "Erreur de syntaxe for"),
                    ],
                    "answer": "A",
                    "explain": "Boucle for in ; echo -n sans saut de ligne, puis echo final.",
                },
                {
                    "n": 38,
                    "points": 2,
                    "stem": "Quelle commande <b>liste</b> le contenu de l'archive sans extraire ?",
                    "code": "backup.tar.gz   (créée avec tar czf)",
                    "choices": [
                        ("A", "tar tzf backup.tar.gz"),
                        ("B", "tar xzf backup.tar.gz"),
                        ("C", "gzip -d backup.tar.gz && rm -r *"),
                        ("D", "unzip backup.tar.gz"),
                    ],
                    "answer": "A",
                    "explain": "t = list, z = gzip, f = fichier. x = extract.",
                },
                {
                    "n": 39,
                    "points": 2,
                    "stem": "Que signifie cette sortie ?",
                    "code": "$ id\nuid=1000(awa) gid=1000(awa) groups=1000(awa),27(sudo),100(users)",
                    "choices": [
                        ("A", "awa est root (UID 0)."),
                        ("B", "Compte standard UID 1000, membre du groupe sudo (privilèges délégués possibles)."),
                        ("C", "Compte système UID &lt; 100."),
                        ("D", "Le mot de passe est stocké en clair dans groups."),
                    ],
                    "answer": "B",
                    "explain": "UID 1000 = user humain Debian/Ubuntu ; groupe sudo = sudoers.",
                },
                {
                    "n": 40,
                    "points": 2,
                    "stem": "Un PC ping 8.8.8.8 (OK) mais ping www.lpi.org échoue en « name or service not known ». Cause la plus probable ?",
                    "choices": [
                        ("A", "Pas de connectivité IP du tout."),
                        ("B", "Problème de résolution DNS (client / resolv.conf / serveur DNS)."),
                        ("C", "Sticky bit manquant sur /tmp."),
                        ("D", "Le noyau n'a pas /dev/sda."),
                    ],
                    "answer": "B",
                    "explain": "IP OK (ping numérique) mais le nom ne se résout pas = DNS.",
                },
            ],
        },
    ],
    "minilab": {
        "title": "Mini-lab papier (optionnel formateur — hors barème 52 pts)",
        "intro": (
            "Durée indicative 15 minutes. Écrivez les commandes Bash essentielles. "
            "Le formateur peut attribuer jusqu'à 10 points bonus."
        ),
        "context_title": "Contexte",
        "topo": (
            "Utilisateur : stagiaire (UID 1000), home /home/stagiaire\n"
            "Objectif : préparer un petit projet « notes » puis l'archiver."
        ),
        "tasks": [
            "Créer ~/notes et y un fichier vide rapport.txt (touch).",
            "Écrire un script ~/notes/liste.sh : shebang bash, boucle for sur *.txt, echo de chaque nom ; le rendre exécutable (chmod 755).",
            "Archiver le dossier notes en ~/notes.tar.gz (tar czf).",
            "Afficher les 5 dernières lignes de /var/log/syslog si le fichier existe (tail), sinon expliquer l'alternative dmesg.",
            "Vérifier que rapport.txt est rw-r--r-- (644) et appartient à stagiaire.",
        ],
        "correction": (
            "mkdir -p ~/notes\n"
            "touch ~/notes/rapport.txt\n"
            "cat > ~/notes/liste.sh << 'EOF'\n"
            "#!/bin/bash\n"
            "for f in *.txt; do\n"
            "  echo \"$f\"\n"
            "done\n"
            "EOF\n"
            "chmod 755 ~/notes/liste.sh\n"
            "tar czf ~/notes.tar.gz -C ~ notes\n"
            "tail -n 5 /var/log/syslog   # sinon : dmesg | tail -n 5\n"
            "chmod 644 ~/notes/rapport.txt\n"
            "ls -l ~/notes/rapport.txt"
        ),
    },
}

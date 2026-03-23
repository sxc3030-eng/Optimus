#!/usr/bin/env python3
"""
help_agent.py — Optimus Suite Interactive Help Agent
=========================================================
Standalone pywebview program providing interactive documentation,
feature guides, and activation instructions for all 10 programs.

Launch: python help_agent.py
"""

import json
import os
import sys
import subprocess
import webview

HELP_DIR = os.path.dirname(os.path.abspath(__file__))
SUITE_DIR = os.path.dirname(HELP_DIR)
HTML_FILE = os.path.join(HELP_DIR, "help_dashboard.html")

# ═══════════════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE — All programs, features, and activation guides
# ═══════════════════════════════════════════════════════════════════════

KNOWLEDGE_BASE = {
    "netguard": {
        "name": "NetGuard Pro",
        "name_fr": "NetGuard Pro",
        "icon": "🛡️",
        "port": 8765,
        "description": "Network IDS, packet capture, deep packet inspection, and firewall management.",
        "description_fr": "IDS réseau, capture de paquets, inspection approfondie et gestion du pare-feu.",
        "launcher": "LANCER_NETGUARD.bat",
        "main_file": "netguard.py",
        "settings_file": "netguard_settings.json",
        "features": {
            "packet_capture": {
                "name": "Packet Capture / Capture de paquets",
                "how_to": "Click 'Start Capture' on the dashboard. Requires Npcap installed. Captures are saved in /captures folder.",
                "how_to_fr": "Cliquez 'Démarrer Capture' sur le tableau de bord. Npcap requis. Les captures sont sauvées dans /captures.",
                "admin": True,
                "setting": None
            },
            "ids": {
                "name": "Intrusion Detection / Détection d'intrusion",
                "how_to": "Enable in Settings → IDS → toggle 'suricata_enabled'. Monitors for port scans, brute force, and anomalies.",
                "how_to_fr": "Activer dans Paramètres → IDS → basculer 'suricata_enabled'. Surveille les scans de ports, attaques brute force et anomalies.",
                "admin": False,
                "setting": "suricata_enabled"
            },
            "dpi": {
                "name": "Deep Packet Inspection / Inspection approfondie",
                "how_to": "Enable in Settings → toggle 'dpi_enabled'. Analyzes packet payloads for malicious content.",
                "how_to_fr": "Activer dans Paramètres → basculer 'dpi_enabled'. Analyse le contenu des paquets pour détecter le contenu malveillant.",
                "admin": False,
                "setting": "dpi_enabled"
            },
            "geo_blocking": {
                "name": "Geo-Blocking / Blocage géographique",
                "how_to": "Settings → Geo-Block → add country codes to 'geo_blocked_countries' list (e.g., 'CN', 'RU').",
                "how_to_fr": "Paramètres → Geo-Block → ajouter les codes pays à la liste 'geo_blocked_countries' (ex: 'CN', 'RU').",
                "admin": True,
                "setting": "geo_blocked_countries"
            },
            "threat_history": {
                "name": "Threat History / Historique des menaces",
                "how_to": "Click 'History' tab to view all detected threats with timestamps, severity, and source IPs.",
                "how_to_fr": "Cliquez l'onglet 'Historique' pour voir toutes les menaces détectées avec horodatage, sévérité et IP sources.",
                "admin": False,
                "setting": None
            },
            "ip_blocking": {
                "name": "IP Blocking / Blocage IP",
                "how_to": "Click block icon next to any threat or IP. Uses Windows Firewall (netsh). Requires admin.",
                "how_to_fr": "Cliquez l'icône de blocage à côté d'une menace ou IP. Utilise le pare-feu Windows (netsh). Admin requis.",
                "admin": True,
                "setting": None
            }
        }
    },
    "cleanguard": {
        "name": "CleanGuard Pro",
        "name_fr": "CleanGuard Pro",
        "icon": "🧹",
        "port": 8810,
        "description": "System cleaner, malware scanner, YARA rules engine, and file quarantine.",
        "description_fr": "Nettoyeur système, scanner de malware, moteur de règles YARA et quarantaine de fichiers.",
        "launcher": "LANCER_CLEANGUARD.bat",
        "main_file": "cleanguard/cleanguard.py",
        "settings_file": "cleanguard/cleanguard_settings.json",
        "features": {
            "system_clean": {
                "name": "System Clean / Nettoyage système",
                "how_to": "Click 'Clean System' to remove temp files, browser cache, and system junk.",
                "how_to_fr": "Cliquez 'Nettoyer Système' pour supprimer les fichiers temporaires, cache navigateur et fichiers inutiles.",
                "admin": False,
                "setting": None
            },
            "malware_scan": {
                "name": "Malware Scan / Scan de malware",
                "how_to": "Click 'Scan' → choose Quick, Full, or Custom scan. Threats are quarantined automatically.",
                "how_to_fr": "Cliquez 'Scan' → choisissez Rapide, Complet ou Personnalisé. Les menaces sont mises en quarantaine automatiquement.",
                "admin": False,
                "setting": None
            },
            "yara_rules": {
                "name": "YARA Rules / Règles YARA",
                "how_to": "Add custom .yar files to /cleanguard/signatures/. They are loaded automatically on scan.",
                "how_to_fr": "Ajoutez des fichiers .yar personnalisés dans /cleanguard/signatures/. Ils sont chargés automatiquement lors du scan.",
                "admin": False,
                "setting": None
            },
            "quarantine": {
                "name": "Quarantine / Quarantaine",
                "how_to": "Quarantined files are in /cleanguard/quarantine/. Restore or delete from the Quarantine tab.",
                "how_to_fr": "Les fichiers en quarantaine sont dans /cleanguard/quarantine/. Restaurez ou supprimez depuis l'onglet Quarantaine.",
                "admin": False,
                "setting": None
            }
        }
    },
    "mailshield": {
        "name": "MailShield Pro",
        "name_fr": "MailShield Pro",
        "icon": "📧",
        "port": 8801,
        "description": "Secure email client with phishing detection, SPF/DKIM validation, and attachment scanning.",
        "description_fr": "Client email sécurisé avec détection de phishing, validation SPF/DKIM et scan des pièces jointes.",
        "launcher": "LANCER_MAILSHIELD.bat",
        "main_file": "mailshield/mailshield.py",
        "settings_file": "mailshield/mailshield_settings.json",
        "features": {
            "email_client": {
                "name": "Secure Email / Email sécurisé",
                "how_to": "Configure IMAP/SMTP in Settings. Supports Gmail, Outlook, and custom servers.",
                "how_to_fr": "Configurez IMAP/SMTP dans Paramètres. Supporte Gmail, Outlook et serveurs personnalisés.",
                "admin": False,
                "setting": "imap_server"
            },
            "phishing_detection": {
                "name": "Phishing Detection / Détection phishing",
                "how_to": "Enabled by default. Checks URLs, sender reputation, and header anomalies.",
                "how_to_fr": "Activé par défaut. Vérifie les URLs, la réputation de l'expéditeur et les anomalies d'en-tête.",
                "admin": False,
                "setting": None
            },
            "spf_dkim": {
                "name": "SPF/DKIM Validation",
                "how_to": "Automatic for all incoming emails. Green shield = passed, red = failed.",
                "how_to_fr": "Automatique pour tous les emails entrants. Bouclier vert = passé, rouge = échoué.",
                "admin": False,
                "setting": None
            },
            "attachment_scan": {
                "name": "Attachment Scanning / Scan des pièces jointes",
                "how_to": "All attachments are scanned before download. Suspicious files are quarantined.",
                "how_to_fr": "Toutes les pièces jointes sont scannées avant téléchargement. Les fichiers suspects sont mis en quarantaine.",
                "admin": False,
                "setting": None
            }
        }
    },
    "vpnguard": {
        "name": "VPN Guard Pro",
        "name_fr": "VPN Guard Pro",
        "icon": "🔐",
        "port": 8820,
        "description": "WireGuard VPN client with kill switch, DNS leak protection, and tunnel monitoring.",
        "description_fr": "Client VPN WireGuard avec kill switch, protection contre les fuites DNS et surveillance du tunnel.",
        "launcher": "LANCER_VPNGUARD.bat",
        "main_file": "vpnguard/vpnguard.py",
        "settings_file": "vpnguard/vpnguard_settings.json",
        "features": {
            "vpn_connect": {
                "name": "VPN Connection / Connexion VPN",
                "how_to": "Click 'Connect' on the dashboard. WireGuard must be installed. Admin rights required.",
                "how_to_fr": "Cliquez 'Connecter' sur le tableau de bord. WireGuard doit être installé. Droits admin requis.",
                "admin": True,
                "setting": None
            },
            "kill_switch": {
                "name": "Kill Switch / Coupe-circuit",
                "how_to": "Enable in Settings → toggle 'kill_switch_enabled'. Blocks internet if VPN disconnects.",
                "how_to_fr": "Activer dans Paramètres → basculer 'kill_switch_enabled'. Bloque internet si le VPN se déconnecte.",
                "admin": True,
                "setting": "kill_switch_enabled"
            },
            "dns_leak": {
                "name": "DNS Leak Protection / Protection fuite DNS",
                "how_to": "Automatic when connected. Forces DNS through the VPN tunnel.",
                "how_to_fr": "Automatique une fois connecté. Force le DNS à travers le tunnel VPN.",
                "admin": False,
                "setting": None
            },
            "peer_management": {
                "name": "Peer Management / Gestion des pairs",
                "how_to": "Settings → Peers → Add/remove VPN peers. Configurations stored in /wireguard/.",
                "how_to_fr": "Paramètres → Pairs → Ajouter/supprimer des pairs VPN. Configurations dans /wireguard/.",
                "admin": True,
                "setting": None
            }
        }
    },
    "sentinel_mapper": {
        "name": "SentinelOS Mapper",
        "name_fr": "SentinelOS Mapper",
        "icon": "🗺️",
        "port": None,
        "description": "Interactive network map with device discovery, firewall management, and multi-interface scanning.",
        "description_fr": "Carte réseau interactive avec découverte d'appareils, gestion du pare-feu et scan multi-interface.",
        "launcher": "LANCER_SENTINEL_MAPPER.bat",
        "main_file": "sentinel/sentinel_mapper.py",
        "settings_file": "sentinel/sentinel_settings.json",
        "features": {
            "network_scan": {
                "name": "Network Scan / Scan réseau",
                "how_to": "Click 'Scan' button. Scans all network interfaces (Wi-Fi, Ethernet, VPN).",
                "how_to_fr": "Cliquez le bouton 'Scan'. Scanne toutes les interfaces réseau (Wi-Fi, Ethernet, VPN).",
                "admin": False,
                "setting": None
            },
            "firewall": {
                "name": "Device Firewall / Pare-feu appareils",
                "how_to": "Select a device → click 'Block Device' to block all traffic, or toggle individual ports. Requires admin.",
                "how_to_fr": "Sélectionnez un appareil → cliquez 'Bloquer Appareil' pour bloquer tout le trafic, ou basculer des ports individuels. Admin requis.",
                "admin": True,
                "setting": None
            },
            "device_naming": {
                "name": "Device Naming / Nommage des appareils",
                "how_to": "Click on a device name in the right panel to rename it. Press Enter to save.",
                "how_to_fr": "Cliquez sur le nom d'un appareil dans le panneau droit pour le renommer. Appuyez Entrée pour sauver.",
                "admin": False,
                "setting": None
            },
            "deep_scan": {
                "name": "Deep Scan / Scan approfondi",
                "how_to": "Select a device → click 'Deep Scan' for detailed port analysis and service detection.",
                "how_to_fr": "Sélectionnez un appareil → cliquez 'Scan approfondi' pour l'analyse détaillée des ports et la détection des services.",
                "admin": False,
                "setting": None
            }
        }
    },
    "cortex": {
        "name": "SentinelOS Cortex",
        "name_fr": "SentinelOS Cortex",
        "icon": "🧠",
        "port": 8900,
        "description": "Central orchestrator that manages all agents, playbooks, threat intelligence, and alerts.",
        "description_fr": "Orchestrateur central qui gère tous les agents, playbooks, renseignement de menaces et alertes.",
        "launcher": "LANCER_SENTINEL.bat",
        "main_file": "sentinel/cortex.py",
        "settings_file": "sentinel/sentinel_settings.json",
        "features": {
            "agent_management": {
                "name": "Agent Management / Gestion des agents",
                "how_to": "Cortex auto-starts all agents. Dashboard shows agent status, health, and communication.",
                "how_to_fr": "Cortex démarre automatiquement tous les agents. Le tableau de bord montre le statut, la santé et la communication des agents.",
                "admin": False,
                "setting": None
            },
            "playbooks": {
                "name": "Playbooks / Scénarios",
                "how_to": "Configure automated response playbooks in the Cortex dashboard. Chain actions across agents.",
                "how_to_fr": "Configurez des scénarios de réponse automatisés dans le tableau de bord Cortex. Enchaînez des actions entre agents.",
                "admin": True,
                "setting": None
            },
            "threat_intel": {
                "name": "Threat Intelligence / Renseignement de menaces",
                "how_to": "Aggregates threat data from all agents. Enable external feeds in settings.",
                "how_to_fr": "Agrège les données de menaces de tous les agents. Activez les flux externes dans les paramètres.",
                "admin": False,
                "setting": None
            },
            "alerts": {
                "name": "Alert System / Système d'alertes",
                "how_to": "Configure Telegram/Discord notifications in alert_manager settings.",
                "how_to_fr": "Configurez les notifications Telegram/Discord dans les paramètres du gestionnaire d'alertes.",
                "admin": False,
                "setting": None
            }
        }
    },
    "fim": {
        "name": "File Integrity Monitor",
        "name_fr": "Moniteur d'intégrité de fichiers",
        "icon": "📁",
        "port": 8840,
        "description": "Monitors file system for unauthorized changes using SHA-256 hashing.",
        "description_fr": "Surveille le système de fichiers pour les changements non autorisés en utilisant le hachage SHA-256.",
        "launcher": None,
        "main_file": "fim/file_integrity_monitor.py",
        "settings_file": None,
        "features": {
            "file_monitoring": {
                "name": "File Monitoring / Surveillance de fichiers",
                "how_to": "Add directories to watch list. FIM computes SHA-256 hashes and alerts on changes.",
                "how_to_fr": "Ajoutez des répertoires à la liste de surveillance. FIM calcule les hashes SHA-256 et alerte en cas de changement.",
                "admin": False,
                "setting": None
            },
            "baseline": {
                "name": "Baseline / Référence",
                "how_to": "Create initial baseline with 'Create Baseline'. All future changes are compared against it.",
                "how_to_fr": "Créez la référence initiale avec 'Créer Référence'. Tous les changements futurs sont comparés à celle-ci.",
                "admin": False,
                "setting": None
            }
        }
    },
    "honeypot": {
        "name": "Honeypot",
        "name_fr": "Pot de miel",
        "icon": "🍯",
        "port": 8830,
        "description": "Deception traps that simulate vulnerable services to detect intruders.",
        "description_fr": "Pièges simulant des services vulnérables pour détecter les intrus.",
        "launcher": None,
        "main_file": "honeypot/honeypot.py",
        "settings_file": None,
        "features": {
            "service_traps": {
                "name": "Service Traps / Pièges de services",
                "how_to": "Configure fake services (SSH, FTP, HTTP) in trap settings. Any connection triggers an alert.",
                "how_to_fr": "Configurez de faux services (SSH, FTP, HTTP) dans les paramètres de piège. Toute connexion déclenche une alerte.",
                "admin": True,
                "setting": None
            },
            "attacker_profiling": {
                "name": "Attacker Profiling / Profilage d'attaquant",
                "how_to": "View attacker behavior, commands attempted, and origin IP in the logs.",
                "how_to_fr": "Visualisez le comportement de l'attaquant, les commandes tentées et l'IP d'origine dans les logs.",
                "admin": False,
                "setting": None
            }
        }
    },
    "strikeback": {
        "name": "StrikeBack",
        "name_fr": "StrikeBack",
        "icon": "⚔️",
        "port": 8850,
        "description": "Active defense module with automated counter-measures against detected threats.",
        "description_fr": "Module de défense active avec contre-mesures automatisées contre les menaces détectées.",
        "launcher": None,
        "main_file": "strikeback/strikeback.py",
        "settings_file": None,
        "features": {
            "auto_block": {
                "name": "Auto Block / Blocage automatique",
                "how_to": "Automatically blocks IPs that trigger threat thresholds. Configure sensitivity in settings.",
                "how_to_fr": "Bloque automatiquement les IPs qui dépassent les seuils de menace. Configurez la sensibilité dans les paramètres.",
                "admin": True,
                "setting": None
            },
            "counter_measures": {
                "name": "Counter-Measures / Contre-mesures",
                "how_to": "Enable specific counter-actions: rate limiting, connection reset, traffic shaping.",
                "how_to_fr": "Activez des contre-actions spécifiques : limitation de débit, réinitialisation de connexion, mise en forme du trafic.",
                "admin": True,
                "setting": None
            }
        }
    },
    "recorder": {
        "name": "Recorder",
        "name_fr": "Enregistreur",
        "icon": "🎙️",
        "port": 8860,
        "description": "Forensic recording of network events, system changes, and security incidents.",
        "description_fr": "Enregistrement forensique des événements réseau, changements système et incidents de sécurité.",
        "launcher": None,
        "main_file": "recorder/recorder.py",
        "settings_file": None,
        "features": {
            "event_recording": {
                "name": "Event Recording / Enregistrement d'événements",
                "how_to": "Start recording to capture all security events. Saved in /recorder/recordings/.",
                "how_to_fr": "Démarrez l'enregistrement pour capturer tous les événements de sécurité. Sauvés dans /recorder/recordings/.",
                "admin": False,
                "setting": None
            },
            "playback": {
                "name": "Playback / Lecture",
                "how_to": "Browse recorded sessions and replay event timelines for forensic analysis.",
                "how_to_fr": "Parcourez les sessions enregistrées et rejouez les chronologies d'événements pour l'analyse forensique.",
                "admin": False,
                "setting": None
            }
        }
    },
    "redteam": {
        "name": "RedTeam Agent",
        "name_fr": "Agent RedTeam",
        "icon": "🎯",
        "port": 8870,
        "description": "Penetration testing toolkit with automated vulnerability scanning and exploit simulation.",
        "description_fr": "Boite a outils de test de penetration avec scan de vulnerabilites automatise et simulation d'exploits.",
        "launcher": None,
        "main_file": "redteam/redteam.py",
        "settings_file": "redteam/redteam_settings.json",
        "features": {
            "vuln_scan": {
                "name": "Vulnerability Scan / Scan de vulnerabilites",
                "how_to": "Launch a vulnerability scan against target hosts. Identifies open ports, weak configs, and known CVEs.",
                "how_to_fr": "Lancez un scan de vulnerabilites contre les hotes cibles. Identifie les ports ouverts, configs faibles et CVEs connues.",
                "admin": True,
                "setting": None
            },
            "exploit_sim": {
                "name": "Exploit Simulation / Simulation d'exploits",
                "how_to": "Run safe exploit simulations to test defenses without causing damage. Results logged for review.",
                "how_to_fr": "Executez des simulations d'exploits securisees pour tester les defenses sans causer de dommages. Resultats enregistres.",
                "admin": True,
                "setting": None
            },
            "report": {
                "name": "Pentest Report / Rapport de pentest",
                "how_to": "Generate detailed penetration test reports with findings, risk levels, and remediation steps.",
                "how_to_fr": "Generez des rapports de test de penetration detailles avec resultats, niveaux de risque et etapes de remediation.",
                "admin": False,
                "setting": None
            }
        }
    },
    "siem": {
        "name": "SIEM Agent",
        "name_fr": "Agent SIEM",
        "icon": "🧠",
        "port": 8880,
        "description": "Security information and event management — collects, correlates, and analyzes security logs.",
        "description_fr": "Gestion des informations et evenements de securite — collecte, correle et analyse les logs de securite.",
        "launcher": None,
        "main_file": "siem/siem.py",
        "settings_file": "siem/siem_settings.json",
        "features": {
            "log_collection": {
                "name": "Log Collection / Collecte de logs",
                "how_to": "Aggregates logs from all agents and system sources. Configure sources in SIEM settings.",
                "how_to_fr": "Agrege les logs de tous les agents et sources systeme. Configurez les sources dans les parametres SIEM.",
                "admin": False,
                "setting": None
            },
            "correlation": {
                "name": "Event Correlation / Correlation d'evenements",
                "how_to": "Automatically correlates events across agents to detect complex attack patterns.",
                "how_to_fr": "Correle automatiquement les evenements entre agents pour detecter les schemas d'attaque complexes.",
                "admin": False,
                "setting": None
            },
            "dashboards": {
                "name": "SIEM Dashboards / Tableaux de bord SIEM",
                "how_to": "View real-time security dashboards with event timelines, top threats, and trend analysis.",
                "how_to_fr": "Visualisez les tableaux de bord securite en temps reel avec chronologies, menaces principales et analyse de tendances.",
                "admin": False,
                "setting": None
            }
        }
    },
    "sandbox": {
        "name": "Sandbox Agent",
        "name_fr": "Agent Sandbox",
        "icon": "📦",
        "port": 8890,
        "description": "Dynamic file analysis in an isolated environment for safe malware detection and behavior analysis.",
        "description_fr": "Analyse dynamique de fichiers en environnement isole pour detection securisee de malware et analyse comportementale.",
        "launcher": None,
        "main_file": "sandbox/sandbox.py",
        "settings_file": "sandbox/sandbox_settings.json",
        "features": {
            "file_analysis": {
                "name": "File Analysis / Analyse de fichiers",
                "how_to": "Drop a suspicious file into the sandbox. It runs in isolation and reports behavior, network calls, and file changes.",
                "how_to_fr": "Deposez un fichier suspect dans le sandbox. Il s'execute en isolation et rapporte le comportement, appels reseau et modifications.",
                "admin": True,
                "setting": None
            },
            "behavior_report": {
                "name": "Behavior Report / Rapport de comportement",
                "how_to": "After analysis, view detailed report: processes spawned, registry changes, network connections, and verdict.",
                "how_to_fr": "Apres analyse, consultez le rapport detaille : processus lances, modifications registre, connexions reseau et verdict.",
                "admin": False,
                "setting": None
            },
            "auto_submit": {
                "name": "Auto-Submit / Soumission automatique",
                "how_to": "Enable auto-submit in settings to automatically sandbox suspicious files detected by other agents.",
                "how_to_fr": "Activez la soumission automatique dans les parametres pour sandboxer les fichiers suspects detectes par d'autres agents.",
                "admin": False,
                "setting": "auto_submit_enabled"
            }
        }
    },
    "mobile_gateway": {
        "name": "Mobile Gateway",
        "name_fr": "Passerelle Mobile",
        "icon": "📱",
        "port": 8895,
        "description": "Mobile device gateway for remote monitoring, push notifications, and mobile dashboard access.",
        "description_fr": "Passerelle mobile pour surveillance a distance, notifications push et acces au tableau de bord mobile.",
        "launcher": None,
        "main_file": "mobile_gateway/mobile_gateway.py",
        "settings_file": "mobile_gateway/mobile_gateway_settings.json",
        "features": {
            "remote_monitoring": {
                "name": "Remote Monitoring / Surveillance a distance",
                "how_to": "Access your security dashboard from any mobile device via the gateway URL. Requires network access.",
                "how_to_fr": "Accedez a votre tableau de bord securite depuis n'importe quel appareil mobile via l'URL de la passerelle.",
                "admin": False,
                "setting": None
            },
            "push_notifications": {
                "name": "Push Notifications / Notifications push",
                "how_to": "Configure push notification endpoints in settings. Receive real-time threat alerts on mobile.",
                "how_to_fr": "Configurez les endpoints de notifications push dans les parametres. Recevez les alertes de menaces en temps reel sur mobile.",
                "admin": False,
                "setting": None
            },
            "api_access": {
                "name": "API Access / Acces API",
                "how_to": "RESTful API for integration with mobile apps. Token-based authentication for secure access.",
                "how_to_fr": "API RESTful pour integration avec les applications mobiles. Authentification par jeton pour acces securise.",
                "admin": True,
                "setting": None
            }
        }
    }
}

# Architecture info
ARCHITECTURE = {
    "overview": "Optimus Suite is a modular cybersecurity platform. Each program runs independently or orchestrated by SentinelOS Cortex.",
    "overview_fr": "Optimus Suite est une plateforme de cybersécurité modulaire. Chaque programme fonctionne indépendamment ou orchestré par SentinelOS Cortex.",
    "ports": {
        "NetGuard Pro": 8765,
        "MailShield Pro": 8801,
        "CleanGuard Pro": 8810,
        "VPN Guard Pro": 8820,
        "Honeypot": 8830,
        "FIM": 8840,
        "StrikeBack": 8850,
        "Recorder": 8860,
        "RedTeam": 8870,
        "SIEM": 8880,
        "Sandbox": 8890,
        "Mobile Gateway": 8895,
        "Cortex": 8900
    }
}

FAQ = [
    {
        "q": "How do I start all programs at once?",
        "q_fr": "Comment démarrer tous les programmes en même temps ?",
        "a": "Use the SentinelOS Cortex launcher (LANCER_SENTINEL.bat). Cortex will start and manage all agents automatically.",
        "a_fr": "Utilisez le lanceur SentinelOS Cortex (LANCER_SENTINEL.bat). Cortex démarrera et gérera tous les agents automatiquement."
    },
    {
        "q": "Do I need admin rights?",
        "q_fr": "Ai-je besoin de droits administrateur ?",
        "a": "Admin rights are needed for: firewall operations, VPN connections, packet capture, and IP blocking. Other features work without admin.",
        "a_fr": "Les droits admin sont nécessaires pour : opérations pare-feu, connexions VPN, capture de paquets et blocage IP. Les autres fonctionnalités marchent sans admin."
    },
    {
        "q": "How do I enable the permission system?",
        "q_fr": "Comment activer le système de permissions ?",
        "a": "Go to any program's Settings → Permissions → Enable. Create a master admin account. Then lock permissions to require authentication.",
        "a_fr": "Allez dans Paramètres de n'importe quel programme → Permissions → Activer. Créez un compte administrateur maître. Puis verrouillez pour exiger l'authentification."
    },
    {
        "q": "What dependencies do I need?",
        "q_fr": "Quelles dépendances ai-je besoin ?",
        "a": "Python 3.10+, pip packages (auto-installed by launchers). Optional: Npcap (packet capture), WireGuard (VPN).",
        "a_fr": "Python 3.10+, paquets pip (installés automatiquement par les lanceurs). Optionnel : Npcap (capture de paquets), WireGuard (VPN)."
    },
    {
        "q": "Where are logs stored?",
        "q_fr": "Où sont stockés les logs ?",
        "a": "Each program has its own /logs folder inside its directory. Cortex aggregates all logs.",
        "a_fr": "Chaque programme a son propre dossier /logs dans son répertoire. Cortex agrège tous les logs."
    }
]


class HelpAgentAPI:
    """pywebview API for the Help Agent dashboard."""

    def get_knowledge_base(self) -> str:
        return json.dumps(KNOWLEDGE_BASE)

    def get_architecture(self) -> str:
        return json.dumps(ARCHITECTURE)

    def get_faq(self) -> str:
        return json.dumps(FAQ)

    def search(self, query: str) -> str:
        """Search across all programs, features, and FAQ."""
        query = query.lower().strip()
        if not query:
            return json.dumps([])

        results = []
        for prog_id, prog in KNOWLEDGE_BASE.items():
            # Search program name and description
            if query in prog["name"].lower() or query in prog.get("description", "").lower() or query in prog.get("description_fr", "").lower():
                results.append({
                    "type": "program",
                    "program": prog_id,
                    "name": prog["name"],
                    "icon": prog["icon"],
                    "match": prog["description"]
                })
            # Search features
            for feat_id, feat in prog.get("features", {}).items():
                if query in feat["name"].lower() or query in feat.get("how_to", "").lower() or query in feat.get("how_to_fr", "").lower():
                    results.append({
                        "type": "feature",
                        "program": prog_id,
                        "program_name": prog["name"],
                        "feature": feat_id,
                        "name": feat["name"],
                        "icon": prog["icon"],
                        "match": feat["how_to"]
                    })

        # Search FAQ
        for faq in FAQ:
            if query in faq["q"].lower() or query in faq["a"].lower() or query in faq.get("q_fr", "").lower():
                results.append({
                    "type": "faq",
                    "question": faq["q"],
                    "answer": faq["a"],
                    "icon": "❓"
                })

        return json.dumps(results[:20])  # max 20 results

    def launch_program(self, launcher: str) -> str:
        """Launch a program via its batch launcher."""
        launcher_path = os.path.join(SUITE_DIR, "launchers", launcher)
        if not os.path.exists(launcher_path):
            return json.dumps({"error": f"Launcher not found: {launcher}"})
        try:
            subprocess.Popen(
                ["cmd.exe", "/c", "start", "", launcher_path],
                cwd=os.path.join(SUITE_DIR, "launchers")
            )
            return json.dumps({"ok": True, "message": f"Launching {launcher}..."})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_suite_info(self) -> str:
        """Return suite version and status info."""
        return json.dumps({
            "version": "3.0.0",
            "programs": len(KNOWLEDGE_BASE),
            "total_features": sum(len(p.get("features", {})) for p in KNOWLEDGE_BASE.values()),
            "suite_dir": SUITE_DIR
        })


def main():
    api = HelpAgentAPI()

    if not os.path.exists(HTML_FILE):
        print(f"[!] Dashboard not found: {HTML_FILE}")
        sys.exit(1)

    window = webview.create_window(
        "Optimus Help — Cybersecurity Suite",
        HTML_FILE,
        js_api=api,
        width=1200,
        height=800,
        min_size=(900, 600),
        background_color="#0f0f13",
        text_select=True
    )
    webview.start(debug=False)


if __name__ == "__main__":
    main()

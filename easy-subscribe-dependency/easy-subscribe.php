<?php
/*
Plugin Name: EasySubscribe Dependencies & Authentication
Description: Carica le dipendenze di Composer per EasySubscribe e abilita l'autenticazione per i file da proteggere.
Author: Giovanni Lamarmora
Version: 2.0.0
*/

function crea_htpasswd_wp() {
    // Ottieni le credenziali dalle impostazioni del plugin
    $user = get_option('wpb_username');
    $password = get_option('wpb_password');
    $protection_enabled = get_option('wpb_enable_protection');

    // Percorso del file .htpasswd
    $htpasswd_path = ABSPATH . '.htpasswd';

    // Se la protezione è abilitata
    if ($protection_enabled) {
        // Verifica che le credenziali siano valide
        if (!$user || !$password) {
            error_log('Username o password non definiti nelle impostazioni del plugin.');
            return;
        }

        // Se il file .htpasswd esiste
        if (file_exists($htpasswd_path)) {
            // Leggi il contenuto del file .htpasswd
            $htpasswd_content = file_get_contents($htpasswd_path);

            // Verifica che il file contenga le credenziali nel formato corretto
            if (strpos($htpasswd_content, ":") !== false) {
                list($existing_user, $existing_password) = explode(":", $htpasswd_content);

                // Verifica se l'utente corrisponde
                if ($existing_user === $user) {
                    // La password esiste già, quindi verifichiamo se è la stessa
                    if (password_verify($password, $existing_password)) {
                        return; // Non fare nulla se la password non è cambiata
                    } else {
                        // La password è cambiata, quindi procediamo a riscrivere il file
                        error_log('La password nel file .htpasswd è cambiata. Aggiornamento necessario.');
                    }
                }
            }
        } else {
            error_log('Il file .htpasswd non esiste. Verrà creato.');
        }

        // Cripta la nuova password usando bcrypt
        $htpasswd_password = password_hash($password, PASSWORD_BCRYPT);

        // Crea o aggiorna il file .htpasswd
        $htpasswd_content = $user . ":" . $htpasswd_password;
        $file_written = file_put_contents($htpasswd_path, $htpasswd_content);

        if ($file_written === false) {
            error_log('Errore nella scrittura del file .htpasswd');
        } else {
            error_log('File .htpasswd aggiornato con successo');
            chmod($htpasswd_path, 0600); // Imposta i permessi corretti
        }
    } else {
        // Se la protezione è disabilitata, rimuovi il file .htpasswd se esiste
        if (file_exists($htpasswd_path)) {
            unlink($htpasswd_path);
            error_log('File .htpasswd rimosso');
        }
    }
}

function crea_htaccess_per_htpasswd() {
    // Controlla se la protezione è abilitata
    $protection_enabled = get_option('wpb_enable_protection');
    $htaccess_path = ABSPATH . '.htaccess'; // Usa la root di WordPress

    // Verifica se il file .htaccess è presente
    if (!file_exists($htaccess_path)) {
        return; // Se il file .htaccess non esiste, esci
    }

    // Leggi il contenuto del file .htaccess
    $htaccess_content = file_get_contents($htaccess_path);

    // Se la protezione è abilitata
    if ($protection_enabled) {
        // Aggiungi la configurazione per proteggere .htpasswd
        $htaccess_config = "\n# Protezione .htpasswd\n";
        $htaccess_config .= "<Files \".htpasswd\">\n";
        $htaccess_config .= "    Order Allow,Deny\n";
        $htaccess_config .= "    Deny from all\n"; // Impedisce l'accesso pubblico al file .htpasswd
        $htaccess_config .= "</Files>\n";

        // Aggiungi la configurazione solo se non è già presente
        if (strpos($htaccess_content, '# Protezione .htpasswd') === false) {
            file_put_contents($htaccess_path, $htaccess_config, FILE_APPEND);
            error_log('Configurazione .htpasswd aggiunta');
        }
    } else {
        // Controlla se la configurazione di protezione .htpasswd è presente prima di rimuoverla
        if (strpos($htaccess_content, '# Protezione .htpasswd') !== false) {
            // Rimuovi la configurazione se la protezione è disabilitata
            $htaccess_content = preg_replace('/# Protezione .htpasswd.*?<\/Files>/s', '', $htaccess_content);
            // Rimuovi eventuali righe vuote in eccesso
            $htaccess_content = preg_replace('/\n\s*\n/', "\n", $htaccess_content);
            file_put_contents($htaccess_path, $htaccess_content);
            error_log('Configurazione .htpasswd rimossa');
        }
    }
}


// Funzione per creare/rimuovere la configurazione nel file .htaccess
function crea_htaccess_per_debug_log() {
    // Controlla se la protezione è abilitata
    $protection_enabled = get_option('wpb_enable_protection');
    $logs_protection_enabled = get_option('wpb_enable_protection_log');
    $htaccess_path = ABSPATH . '.htaccess'; // Usa la root di WordPress

    // Verifica se il file .htaccess è presente
    if (!file_exists($htaccess_path)) {
        return; // Se il file .htaccess non esiste, esci
    }

    // Leggi il contenuto del file .htaccess
    $htaccess_content = file_get_contents($htaccess_path);

    // Se la protezione dei log è abilitata
    if ($protection_enabled && $logs_protection_enabled) {
        // Aggiungi la configurazione per proteggere debug.log
        $htaccess_config = "\n# Protezione debug.log\n";
        $htaccess_config .= "<Files \"debug.log\">\n";
        $htaccess_config .= "    AuthType Basic\n";
        $htaccess_config .= "    AuthName \"Restricted Access\"\n";
        $htaccess_config .= "    AuthUserFile " . ABSPATH . ".htpasswd\n"; // Percorso assoluto al file .htpasswd
        $htaccess_config .= "    Require valid-user\n";
        $htaccess_config .= "</Files>\n";

        // Aggiungi la configurazione solo se non è già presente
        if (strpos($htaccess_content, '# Protezione debug.log') === false) {
            file_put_contents($htaccess_path, $htaccess_config, FILE_APPEND);
            error_log('Configurazione debug.log aggiunta');
        }
    } else if ($logs_protection_enabled && !$protection_enabled) {
        // Mostra un errore nelle impostazioni di WordPress se la protezione non è abilitata ma la protezione dei log è attiva
        add_action('admin_notices', function() {
            echo '<div class="error"><p><strong>Errore:</strong> La protezione tramite .htpasswd è disabilitata, ma la protezione dei log è abilitata. Per favore, abilita la protezione tramite .htpasswd nelle impostazioni del plugin.</p></div>';
        });
    } else {
        // Controlla se la configurazione di protezione debug.log è presente prima di rimuoverla
        if (strpos($htaccess_content, '# Protezione debug.log') !== false) {
            // Rimuovi la configurazione se la protezione dei log è disabilitata
            $htaccess_content = preg_replace('/# Protezione debug.log.*?<\/Files>/s', '', $htaccess_content);
            // Rimuovi eventuali righe vuote in eccesso
            $htaccess_content = preg_replace('/\n\s*\n/', "\n", $htaccess_content);
            file_put_contents($htaccess_path, $htaccess_content);
            error_log('Configurazione debug.log rimossa');
        }
    }
}

// Funzione per creare/rimuovere la configurazione nel file .htaccess
function crea_htaccess_per_env() {
    // Controlla se la protezione è abilitata
    $protection_enabled = get_option('wpb_enable_protection');
    $env_protection_enabled = get_option('wpb_enable_protection_env');
    $htaccess_path = ABSPATH . '.htaccess'; // Usa la root di WordPress

    // Verifica se il file .htaccess è presente
    if (!file_exists($htaccess_path)) {
        return; // Se il file .htaccess non esiste, esci
    }

    // Leggi il contenuto del file .htaccess
    $htaccess_content = file_get_contents($htaccess_path);

    // Se la protezione dei log è abilitata
    if ($protection_enabled && $env_protection_enabled) {
        // Aggiungi la configurazione per proteggere debug.log
        $htaccess_config = "\n# Protezione .env\n";
        $htaccess_config .= "<Files \".env\">\n";
        $htaccess_config .= "    AuthType Basic\n";
        $htaccess_config .= "    AuthName \"Restricted Access\"\n";
        $htaccess_config .= "    AuthUserFile " . ABSPATH . ".htpasswd\n"; // Percorso assoluto al file .htpasswd
        $htaccess_config .= "    Require valid-user\n";
        $htaccess_config .= "</Files>\n";

        // Aggiungi la configurazione solo se non è già presente
        if (strpos($htaccess_content, '# Protezione .env') === false) {
            file_put_contents($htaccess_path, $htaccess_config, FILE_APPEND);
            error_log('Configurazione .env aggiunta');
        }
    } else if ($env_protection_enabled && !$protection_enabled) {
        // Mostra un errore nelle impostazioni di WordPress se la protezione non è abilitata ma la protezione dei log è attiva
        add_action('admin_notices', function() {
            echo '<div class="error"><p><strong>Errore:</strong> La protezione tramite .htpasswd è disabilitata, ma la protezione dei .env è abilitata. Per favore, abilita la protezione tramite .htpasswd nelle impostazioni del plugin.</p></div>';
        });
    } else {
        // Controlla se la configurazione di protezione .env è presente prima di rimuoverla
        if (strpos($htaccess_content, '# Protezione .env') !== false) {
            // Rimuovi la configurazione se la protezione .env è disabilitata
            $htaccess_content = preg_replace('/# Protezione .env.*?<\/Files>/s', '', $htaccess_content);
            // Rimuovi eventuali righe vuote in eccesso
            $htaccess_content = preg_replace('/\n\s*\n/', "\n", $htaccess_content);
            file_put_contents($htaccess_path, $htaccess_content);
            error_log('Configurazione .env rimossa');
        }
    }
}

// Aggiungi il menu alle impostazioni
function wpb_plugin_menu() {
    add_options_page(
        'Impostazioni EasySubscribe Authentication', // Titolo della pagina
        'EasySubscribe Authentication', // Nome del menu
        'manage_options', // Permessi
        'wp-basic-auth-settings', // Slug
        'wpb_plugin_settings_page' // Funzione per il contenuto della pagina
    );
}
add_action('admin_menu', 'wpb_plugin_menu');

// Contenuto della pagina delle impostazioni
function wpb_plugin_settings_page() {
    ?>
    <div class="wrap">
        <!-- Logo del plugin -->
        <?php 
        $logo_url = esc_url(get_option('wpb_logo_url', 'https://www.easysubscribe.it/wp-content/uploads/2025/01/easy.png')); 
        ?>
        <img id="pluginLogo" src="<?php echo $logo_url; ?>" alt="Logo Plugin" style="max-width: 200px;" />

        <script>
            // Gestione dell'immagine e del campo di input
            const img = document.getElementById('pluginLogo');
            const logoUrlContainer = document.getElementById('logoUrlInputContainer');

            img.onload = () => {
                console.log("L'immagine è stata caricata correttamente.");
            };

            img.onerror = () => {
                console.log("Errore nel caricamento dell'immagine. Mostro il campo URL.");
                img.style.display = "none"; // Nascondi l'immagine
            };
        </script>

        <h1>EasySubscribe Authentication</h1>

        <form method="post" action="options.php">
            <?php
            settings_fields('wpb_plugin_options_group'); // Gruppo delle opzioni
            do_settings_sections('wp-basic-auth-settings');
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Nome utente</th>
                    <td><input type="text" name="wpb_username" style="width:250px" value="<?php echo esc_attr(get_option('wpb_username')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Password</th>
                    <td>
                        <!-- Campo di input per la password -->
                        <input type="password" id="wpb_password" name="wpb_password" style="width:250px" value="<?php echo esc_attr(get_option('wpb_password')); ?>" />

                        <!-- Checkbox per mostrare/nascondere la password -->
                        <label for="show_password">
                            <input type="checkbox" id="show_password" /> Mostra Password
                        </label>
                        </br>
                        <small>Se non inserisci username e password abilitando la protezione non si avrà accesso ai file .env e LOG.</small>
                    </td>
                </tr>

                <script>
                    // Funzione per alternare la visibilità della password
                    document.getElementById('show_password').addEventListener('change', function() {
                        const passwordField = document.getElementById('wpb_password');
                        if (this.checked) {
                            passwordField.type = 'text';  // Mostra la password
                        } else {
                            passwordField.type = 'password';  // Nasconde la password
                        }
                    });
                </script>
                <tr valign="top">
                    <th scope="row">Abilita protezione</th>
                    <td>
                        <input type="checkbox" name="wpb_enable_protection" value="1" <?php checked(1, get_option('wpb_enable_protection'), true); ?> />
                        Abilita protezione tramite .htpasswd
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row">Protezione LOG</th>
                    <td>
                        <input type="checkbox" name="wpb_enable_protection_log" value="1" <?php checked(1, get_option('wpb_enable_protection_log'), true); ?> />
                        Abilita protezione dei LOGS
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row">Accedi ai LOG</th>
                    <td>
                        <!-- Bottone per accedere ai log -->
                        <a href="<?php echo content_url('debug.log'); ?>" 
                           target="_blank" 
                           class="button">
                            Accedi ai Logs
                        </a>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row">Protezione ENV</th>
                    <td>
                        <input type="checkbox" name="wpb_enable_protection_env" value="1" <?php checked(1, get_option('wpb_enable_protection_env'), true); ?> />
                        Abilita protezione dei ENV
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row">Accedi ai ENV</th>
                    <td>
                        <!-- Bottone per accedere al file .env -->
                        <a href="<?php echo content_url('.env'); ?>" 
                           target="_blank" 
                           class="button">
                            Accedi ai ENV
                        </a>
                    </td>
                </tr>
                <tr valign="top">
                    <th scope="row">URL del Logo (Personalizzato):</th>
                    <td>
                        <!-- Input per l'URL del logo -->
                        <input type="text" id="wpb_logo_url" name="wpb_logo_url" style="width: 400px;" value="<?php echo esc_attr($logo_url); ?>" placeholder="Inserisci URL del logo" />

                        <!-- Bottone per modificare il logo -->
                        <button type="button" id="edit_logo" name="edit_logo" style="width: 100px;" onclick="toggleLogoInput()">Modifica</button>
                    </td>
                    <script>
                        // Funzione per nascondere o mostrare l'input del logo
                        function toggleLogoInput() {
                            const logoInput = document.getElementById('wpb_logo_url');
                            const editButton = document.getElementById('edit_logo');

                            // Controlla se l'immagine del logo esiste
                            const logoImg = document.getElementById('pluginLogo');
                        
                            // Se l'immagine esiste, nascondi l'immagine e mostra l'input
                            if (logoImg && logoImg.complete && logoImg.naturalHeight !== 0) {
                                logoInput.style.display = 'block'; // Mostra l'input
                                editButton.style.display = 'none';  // Cambia il testo del bottone
                            } else {
                                // Se l'immagine non è presente, nascondi l'input e mostra il bottone
                                logoInput.style.display = 'none'; // Nascondi l'input
                                editButton.style.display = 'block'; // Cambia il testo del bottone
                            }
                        }
                    
                        // Inizializza il comportamento del bottone quando la pagina si carica
                        document.addEventListener("DOMContentLoaded", function() {
                            const logoImg = document.getElementById('pluginLogo');
                            const logoInput = document.getElementById('wpb_logo_url');
                            const editButton = document.getElementById('edit_logo');

                            // Se l'immagine è presente, nascondi l'input e mostra il bottone
                            if (logoImg && logoImg.complete && logoImg.naturalHeight !== 0) {
                                logoInput.style.display = 'none'; // Nascondi l'input
                                editButton.style.display = 'block'; // Cambia il testo del bottone
                            } else {
                                logoInput.style.display = 'block'; // Mostra l'input se l'immagine non c'è
                                editButton.style.display = 'none';  // Cambia il testo del bottone
                            }
                        });
                    </script>
                </tr>
                <tr valign="top">
                    <th scope="row">Abilita logo personalizzato nella login</th>
                    <td>
                        <input type="checkbox" name="wpb_enable_custom_login_logo" value="1" <?php checked(1, get_option('wpb_enable_custom_login_logo'), true); ?> />
                        Mostra questo logo nella schermata di login
                    </td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>
    </div>
    <?php
}

// Registra le opzioni nelle impostazioni di WordPress
function wpb_plugin_register_settings() {
    register_setting('wpb_plugin_options_group', 'wpb_logo_url'); // Aggiunta per il logo personalizzato
    register_setting('wpb_plugin_options_group', 'wpb_username');
    register_setting('wpb_plugin_options_group', 'wpb_password');
    register_setting('wpb_plugin_options_group', 'wpb_enable_protection');
    register_setting('wpb_plugin_options_group', 'wpb_enable_protection_log');
    register_setting('wpb_plugin_options_group', 'wpb_enable_protection_env');
    register_setting('wpb_plugin_options_group', 'wpb_enable_custom_login_logo'); // Registra l'opzione del logo personalizzato
}
add_action('admin_init', 'wpb_plugin_register_settings');

// Attiva la creazione del file .htpasswd al caricamento del plugin
add_action('init', 'crea_htpasswd_wp');

// Attiva la creazione del file .htaccess al caricamento del plugin
add_action('init', 'crea_htaccess_per_debug_log');

add_action('init', 'crea_htaccess_per_env');
add_action('init', 'crea_htaccess_per_htpasswd');

// Aggiungi il link "Impostazioni" nella lista dei plugin
function wpb_add_settings_link($links) {
    // Crea il link alle impostazioni del plugin
    $settings_link = '<a href="options-general.php?page=wp-basic-auth-settings">Impostazioni</a>';
    
    // Aggiungi il link al menu delle azioni del plugin
    array_unshift($links, $settings_link);  // Aggiunge il link all'inizio della lista
    return $links;
}
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'wpb_add_settings_link');

// Funzione per verificare se il logo è accessibile
function wpb_is_logo_accessible($logo_url) {
    $headers = @get_headers($logo_url);
    return $headers && strpos($headers[0], '200') !== false;
}

// Aggiungi logo personalizzato alla schermata di login
function wpb_custom_login_logo() {
    $logo_url = esc_url(get_option('wpb_logo_url', ''));
    $enable_custom_logo = get_option('wpb_enable_custom_login_logo', 0);

    // Verifica se il logo è abilitato e se è accessibile
    if ($enable_custom_logo && $logo_url && wpb_is_logo_accessible($logo_url)) {
        echo '<style type="text/css">
            body.login div#login h1 a {
                background-image: url(' . $logo_url . ');
                background-size: contain;
                width: 100%;
                height: 84px; /* Altezza standard del logo */
            }
        </style>';
    }
}
add_action('login_enqueue_scripts', 'wpb_custom_login_logo');


// Carica le dipendenze di Composer se il file autoload.php esiste
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

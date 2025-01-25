<?php
/*
Plugin Name: EasySubscribe Dependencies
Description: Carica le dipendenze di Composer per EasySubscribe.
Author: Giovanni Lamarmora
Version: 1.0
*/

if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}

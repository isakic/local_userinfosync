<?php
// This file is part of Moodle - http://moodle.org/.
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle. If not, see <http://www.gnu.org/licenses/>.

/**
 * @package local
 * @subpackage userinfosync
 * @copyright 2013 Ivan Šakić
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once($CFG->dirroot . '/mnet/environment.php');
require_once($CFG->dirroot . '/mnet/lib.php');
require_once('lib.php');

$mnetenvironment = get_mnet_environment();
$mnetenvironment->get_keypair();

$request = required_param('request', PARAM_RAW);
$plaintextmessage = userinfosync_strip_encryption($request);
$xmlrpcrequest = userinfosync_strip_signature($plaintextmessage);

$method = '';
$params = xmlrpc_decode_request($xmlrpcrequest, $method);
$response = userinfosync_get_local_user_info($params[1], $params[2]);

$responsetext = xmlrpc_encode($response);
$signedresponse = mnet_sign_message($responsetext);
$remotecertificate = $DB->get_field('mnet_host', 'public_key', array('wwwroot' => $params[0]));
$encryptedresponse = mnet_encrypt_message($signedresponse, $remotecertificate);

echo $encryptedresponse;
die;


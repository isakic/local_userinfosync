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

require_once($CFG->dirroot . '/mnet/environment.php');
require_once($CFG->dirroot . '/mnet/lib.php');
require_once('client.php');

/**
 * @param $request
 * @return bool|string
 */
function userinfosync_strip_encryption($request) {
    $crypt_parser = new mnet_encxml_parser();
    $crypt_parser->parse($request);

    if (!$crypt_parser->payload_encrypted) {
        return $request;
    }
    $key  = array_pop($crypt_parser->cipher);
    $data = array_pop($crypt_parser->cipher);
    $crypt_parser->free_resource();

    $payload = '';

    $mnetenvironment = get_mnet_environment();
    $open = openssl_open(base64_decode($data), $payload, base64_decode($key), $mnetenvironment->get_private_key());
    if ($open) {
        return $payload;
    }

    $openssl_history = get_config('mnet', 'openssl_history');
    if (empty($openssl_history)) {
        $openssl_history = array();
        set_config('openssl_history', serialize($openssl_history), 'mnet');
    } else {
        $openssl_history = unserialize($openssl_history);
    }
    foreach ($openssl_history as $keyset) {
        $keyresource = openssl_pkey_get_private($keyset['keypair_PEM']);
        $open = openssl_open(base64_decode($data), $payload, base64_decode($key), $keyresource);
        if ($open) {
            return $payload;
        }
    }

    return false;
}

/**
 * @param $plaintextmessage
 * @return bool|string
 */
function userinfosync_strip_signature($plaintextmessage) {
    global $DB;

    $sig_parser = new mnet_encxml_parser();
    $sig_parser->parse($plaintextmessage);

    if ($sig_parser->signature == '') {
        return $plaintextmessage;
    }

    $payload = base64_decode($sig_parser->data_object);
    $signature = base64_decode($sig_parser->signature);
    $certificate = $DB->get_field('mnet_host', 'public_key', array('wwwroot' => $sig_parser->remote_wwwroot));

    if ($certificate == false) {
        return $payload;
    }

    $signature_verified = openssl_verify($payload, $signature, $certificate);
    $sig_parser->free_resource();

    if ($signature_verified) {
        return $payload;
    } else {
        return false;
    }
}

/**
 * @param array $usernames
 * @param array $fieldnames
 * @return array
 */
function userinfosync_get_local_user_info(array $usernames, array $fieldnames) {
    file_put_contents('C:\wamp\www\moodle\usernames.txt', print_r($usernames, true));
    file_put_contents('C:\wamp\www\moodle\fieldnames.txt', print_r($fieldnames, true));
    global $DB;
    list($insql, $params) = $DB->get_in_or_equal($usernames, SQL_PARAMS_NAMED);
    $query = "SELECT u.username, u.id
                FROM {user} u
               WHERE u.username $insql";
    $usernames = $DB->get_records_sql_menu($query, $params);

    $data = array();
    list($insql, $params) = $DB->get_in_or_equal($fieldnames, SQL_PARAMS_NAMED);
    file_put_contents('C:\wamp\www\moodle\insql.txt', print_r($params, true));
    foreach ($usernames as $username => $userid) {
        $query = "SELECT f.shortname, d.data
                    FROM {user_info_field} f
              INNER JOIN {user_info_data} d ON f.id = d.fieldid
                   WHERE d.userid = :userid
                     AND f.shortname $insql";
        $userinfo = $DB->get_records_sql_menu($query, $params + array('userid' => $userid));
        $data[$username] = $userinfo;
    }
    file_put_contents('C:\wamp\www\moodle\fields.txt', print_r($data, true));
    return $data;
}

/**
 * @param $userids
 */
function userinfosync_update_user_fields($userids) {
    global $DB;

    if (empty($userids)) {
        return;
    }

    list($insql, $params) = $DB->get_in_or_equal($userids);
    $query = "SELECT u.id, u.username, u.mnethostid
                    FROM {user} u
              INNER JOIN {mnet_host} h ON u.mnethostid = h.id
                   WHERE u.id $insql
                     AND u.auth LIKE 'mnet'";
    $results = $DB->get_records_sql($query, $params);

    $hostidtousers = array();
    foreach ($results as $result) {
        if (!isset($hostidtousers[$result->mnethostid])) {
            $hostidtousers[$result->mnethostid] = array();
        }
        $hostidtousers[$result->mnethostid][] = $result->username;
    }

    $fieldnames = $DB->get_records_select_menu('user_info_field', '1', array('id', 'shortname'));

    foreach ($hostidtousers as $hostid => $usernames) {
        $url = $DB->get_field('mnet_host', 'wwwroot', array('id' => $hostid));
        $userdata = userinfosync_request_user_info($url, $usernames, $fieldnames);
        foreach ($userdata as $username => $fields) {
            $userid = $DB->get_field('user', 'id', array('username' => $username, 'auth' => 'mnet', 'mnethostid' => $hostid));
            foreach ($fields as $fieldname => $data) {
                $fieldid = array_search($fieldname, $fieldnames);
                if ($DB->record_exists('user_info_data', array('userid' => $userid, 'fieldid' => $fieldid))) {
                    $DB->set_field('user_info_data', 'data', $data, array('userid' => $userid, 'fieldid' => $fieldid));
                } else {
                    $record = array(
                        'userid' => $userid,
                        'fieldid' => $fieldid,
                        'data' => $data,
                    );
                    $DB->insert_record('user_info_data', (object) $record);
                }
            }
        }
    }
}

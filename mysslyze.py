from cryptography.x509 import NameOID, Certificate, ObjectIdentifier, CertificatePolicies, PolicyInformation, ExtensionNotFound
from cryptography.x509.oid import NameOID, ExtensionOID, SignatureAlgorithmOID, CertificatePoliciesOID
from sslyze.plugins.utils.certificate_utils import CertificateUtils

from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand, CertificateInfoScanResult

from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand, AcceptedCipherSuite
from sslyze.synchronous_scanner import SynchronousScanner

import openpyxl
import sqlite3
import requests
import urllib.request, urllib.error

# 接続テスト
def server_connectivity_tester(hn):
    try:
        server_tester = ServerConnectivityTester(
            hostname = hn,
            port = 443,
        )
        
        print(f'\nTesting connectivity with {server_tester.hostname}:{server_tester.port}...')
        server_info = server_tester.perform()
    except ServerConnectivityError as err:
        # Could not establish an SSL connection to the server
        ##raise RuntimeError(f'Could not connect to {err.server_info.hostname}: {err.error_message}')
        print(f'Could not connect to {err.server_info.hostname}: {err.error_message}\n')
        server_info = 'error'
    
    return server_info


# スキャナー本体
def concurrent_scanner(hn):
    # Setup the server to scan and ensure it is online/reachable
    server_info = server_connectivity_tester(hn)
    if server_info is 'error':
        return

    # Run multiple scan commands concurrently.
    concurrent_scanner = ConcurrentScanner()

    # Queue some scan commands
    print('\nQueuing some commands...')
    concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv13ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv11ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Tlsv10ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
    concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand())

    # Process the results
    print('\nProcessing results...')
    for scan_result in concurrent_scanner.get_results():
        # これからスキャンする情報(コマンド)を表示
        print(f'\nReceived result for "{scan_result.scan_command.get_title()}" '
              f'on {scan_result.server_info.hostname}')

        # A scan command can fail (as a bug); it is returned as a PluginRaisedExceptionResult
        # スキャンコマンドのエラー
        if isinstance(scan_result, PluginRaisedExceptionScanResult):
            ##raise RuntimeError(f'Scan command failed: {scan_result.scan_command.get_title()}')
            print(f'Scan command failed: {scan_result.scan_command.get_title()}')
            continue

        # Each scan result has attributes with the information yo're looking for
        # All these attributes are documented within each scan command's module
        if isinstance(scan_result.scan_command, Sslv20ScanCommand):
            # Cipher suitesリスト(ssl2.0)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, SSL20) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)
        
        if isinstance(scan_result.scan_command, Sslv30ScanCommand):
            # Cipher suitesリスト(ssl3.0)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, SSL30) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)
        
        if isinstance(scan_result.scan_command, Tlsv10ScanCommand):
            # Cipher suitesリスト(tls1.0)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, TLS10) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)
    
        if isinstance(scan_result.scan_command, Tlsv11ScanCommand):
            # Cipher suitesリスト(tls1.1)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, TLS11) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)
    
        if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
            # Cipher suitesリスト(tls1.2)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, TLS12) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)

        if isinstance(scan_result.scan_command, Tlsv13ScanCommand):
            # Cipher suitesリスト(tls1.3)を表示
            for cipher in scan_result.accepted_cipher_list:
                print(f'    {cipher.name}')
                sql = "INSERT INTO CipherSuite(hostname, TLS13) values(?, ?)"
                data = [(hn, cipher.name)]
                cur.executemany(sql, data)
        
        elif isinstance(scan_result.scan_command, CertificateInfoScanCommand):
            # Print the Common Names within the verified certificate chain
            # 証明書情報を表示
            if not scan_result.verified_certificate_chain:
                print('Error: certificate chain is not trusted!')
                cur.execute("INSERT INTO CertInfo(hostname) values(?)", [hn])
                

            else:
                print('Certificate chain common names:')
                for cert in scan_result.verified_certificate_chain:
                    cert_common_names_check = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if cert_common_names_check:
                        cert_common_names = cert_common_names_check[0].value
                    else:
                        cert_common_names = ''
                    cert_publickey = CertificateUtils.get_public_key_type(cert)
                    cert_keysize = cert.public_key().key_size
                    cert_sig_algo = cert.signature_algorithm_oid
                    cert_leaf_ev = scan_result.leaf_certificate_is_ev # leafのみ

                    # Policy type 判定未完成↓
                    """
                    try:
                        cert_policy = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
                    except ExtensionNotFound:
                        continue
                    OV = '2.23.140.1.2.2'
                    DV = '2.23.140.1.2.1'
                    if OV in cert_policy:
                        cert_policy_type = 'OV'
                    if DV in cert_policy:
                        cert_policy_type = 'DV'
                    else:
                        cert_policy_type = ''
                    """

                    cert_ov_check = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    if cert_ov_check:
                        cert_ov = cert_ov_check[0].value
                    else:
                        cert_ov = ''
                    print(f'   {cert_common_names}')
                    print(f'   {cert_publickey}')
                    print(f'   {cert_keysize}')
                    print(f'   {cert_sig_algo._name}')
                    # print(f'   {cert_policy_type}')
                    print(f'   {cert_leaf_ev}')
                    print(f'   {cert_ov}')

                    sql = "INSERT INTO CertInfo(hostname, commonname, publickey, keysize, signature, certtype, ov) values(?, ?, ?, ?, ?, ?, ?)"
                    data = [(hn, cert_common_names, cert_publickey, cert_keysize, cert_sig_algo._name, cert_leaf_ev, cert_ov)]
                    cur.executemany(sql, data)




if __name__ == '__main__':

    # mysslyze.dbを作成
    # すでに存在していれば、それにアスセス
    dbname = './Documents/python/test.db'
    conn = sqlite3.connect(dbname)
    # sqliteを操作するカーソルオブジェクトを作成
    cur = conn.cursor()

    # tableを作成
    tb1 = """CREATE TABLE IF NOT EXISTS Redirect(
                hostname text,
                urla text,
                urlb text,
                https integer
                );"""
    
    tb2 = """CREATE TABLE IF NOT EXISTS CertInfo(
                hostname text,
                commonname text,
                publickey text,
                keysize integer,
                signature text,
                certtype integer,
                ov text
                );"""

    tb3 = """CREATE TABLE IF NOT EXISTS CipherSuite(
                hostname text,
                SSL20 text,
                SSL30 text,
                TLS10 text,
                TLS11 text,
                TLS12 text,
                TLS13 text
                );"""

    cur.execute(tb1)
    cur.execute(tb2)
    cur.execute(tb3)

    # 調査対象ドメインリスト
    wbi = openpyxl.load_workbook('./Documents/python/sample.xlsx')
    wsi = wbi['Sheet1']

    i = 1

    # シート内の3列目のセルの値を順に取得
    for cell_obj in list(wsi.columns)[2]:
        src_url = cell_obj.value

        # リストに記載された元々のホスト名
        url_mod1 = cell_obj.value.replace('http://', '', 1).replace('https://', '', 1)
        url_mod2 = url_mod1.rstrip('/')
        url_mod3 = url_mod2.split('/')[0]
        hn_orig = url_mod3

        # 存在確認
        print(f'\n---------------------------------------------')

        # アクセスできるか確認
        try:
            f = urllib.request.urlopen(src_url)
            print ("OK:" + src_url )
            f.close()

            # リダイレクト調査
            res = requests.get(src_url)
            print('request_url:', src_url)

            res_url = res.url
            history = res.history
            # リダイレクトあり
            if history:
                print('history_status_code:', history[0].status_code)
                insert_res_url = res_url

                # sslyzeに渡す為、先頭と末尾の不要文字列を削除
                url_mod1 = insert_res_url.replace('http://', '', 1).replace('https://', '', 1)
                url_mod2 = url_mod1.rstrip('/')
                url_mod3 = url_mod2.split('/')[0]
                hn = url_mod3

            # リダイレクトなし
            else:
                response_url = res_url
                insert_res_url = ''

                # sslyzeに渡す為、先頭と末尾の不要文字列を削除
                url_mod1 = response_url.replace('http://', '', 1).replace('https://', '', 1)
                url_mod2 = url_mod1.rstrip('/')
                url_mod3 = url_mod2.split('/')[0]
                hn = url_mod3

            print('response_url:', res_url)

        except:

            # sslyzeに渡すhn  # requestsでアクセスできなくてもhttpsを試したい
            # 日本語ドメインの場合、リダイレクト後のURLを取得
            try:
                res = requests.get(src_url)
                res_url = res.url
            
                url_mod1 = res_url.replace('http://', '', 1).replace('https://', '', 1)
                url_mod2 = url_mod1.rstrip('/')
                url_mod3 = url_mod2.split('/')[0]
                hn = url_mod3
                print('request_url:', src_url)
                print('response_url:', res_url)
                insert_res_url = res_url
            except:
                print ("NotFound:" + src_url)

                url_mod1 = src_url.replace('http://', '', 1).replace('https://', '', 1)
                url_mod2 = url_mod1.rstrip('/')
                url_mod3 = url_mod2.split('/')[0]
                hn = url_mod3
                src_url = ''
                insert_res_url = ''


        sql = "INSERT INTO Redirect(hostname, urla, urlb) values(?, ?, ?)"
        data = [(hn_orig, src_url, insert_res_url)]
        cur.executemany(sql, data)


        i = i+1
        concurrent_scanner(hn)
        
        conn.commit()

    conn.close()

    
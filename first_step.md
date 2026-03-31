**Фаза 1 — Ориентирование.** Первым делом нужно понять масштаб: сколько времени охватывает дамп, какой объём, есть ли временны́е всплески. `capinfos` \+ `io,stat` дают это за секунды.

**Фаза 2 — Карта хостов.** `conv,ip` и `endpoints,ip` показывают топологию без разбора протоколов. Хост с аномально большим числом уникальных dst — скорее всего сканер. Хост с большим входящим объёмом — возможная жертва эксфильтрации.

**Фаза 3 — Признаки атаки.** Короткие TCP-сессии и чистые SYN — классический nmap/masscan. ICMP с payload — возможный туннель (ptunnel, icmpsh).

**Фаза 4 — Прикладной уровень.** HTTP-дерево за 5 секунд покажет брутфорс (сотни 401/403), эксплойт (500), или выгрузку файлов. SNI из TLS помогает даже без расшифровки.

**Фаза 5 — Утечка данных.** FTP, Basic Auth, SMTP без TLS — всё это читается напрямую. В CTF/форензике там часто лежат флаги.

**Фаза 6 — Хронология.** Когда подозреваемый IP найден — `follow,tcp` по конкретному стриму реконструирует весь диалог, включая команды шелла или C2-протокол.

1 — Ориентирование   
Что вообще в файле?  
capinfos capture.pcap  
Длительность, количество пакетов, битрейт, тип линка. Первая точка отсчёта.

tshark \-r capture.pcap \-q \-z io,stat,60  
Трафик по 60-секундным интервалам — видно всплески активности.

tshark \-r capture.pcap \-q \-z ptype,tree  
Распределение по протоколам (TCP/UDP/ICMP/...). Покажет аномалии на уровне L3/L4.

2 — Карта хостов   
Кто с кем общается?  
tshark \-r capture.pcap \-q \-z conv,ip | sort \-k5 \-rn | head \-30  
Топ IP-пар по числу пакетов. Самые «разговорчивые» пары — первые подозреваемые.

tshark \-r capture.pcap \-q \-z endpoints,ip | sort \-k2 \-rn | head \-20  
Топ хостов по объёму — источники и приёмники аномального трафика.

tshark \-r capture.pcap \-T fields \-e ip.src \-e ip.dst \-e dns.qry.name \-Y dns | sort \-u  
Все DNS-запросы — видны C2-домены, DGA-паттерны, tunneling через DNS.

3 — Сканирование / разведка   
Есть ли признаки атаки?

tshark \-r capture.pcap \-q \-z conv,tcp | awk '$10\<3' | sort \-k5 \-rn | head \-20  
TCP-сессии меньше 3 пакетов — классический признак port scan (SYN-only или RST-flood).

tshark \-r capture.pcap \-Y "tcp.flags.syn==1 && tcp.flags.ack==0"  \-T fields \-e ip.src \-e ip.dst \-e tcp.dstport | sort | uniq \-c | sort \-rn | head \-30  
Чистые SYN без ACK — горизонтальный или вертикальный скан.

tshark \-r capture.pcap \-Y "icmp" \\  
  \-T fields \-e ip.src \-e ip.dst \-e icmp.type | sort | uniq \-c | sort \-rn  
ICMP-sweep, ping flood или data-exfil через ICMP payload.

4 — Приложения и данные   
Что передаётся?  
tshark \-r capture.pcap \-q \-z http,tree  
Статистика HTTP: методы, коды ответов, User-Agents. Много 4xx/5xx — брутфорс или эксплойт.

tshark \-r capture.pcap \-Y http.request \\  
  \-T fields \-e ip.src \-e http.host \-e http.request.method \\  
  \-e http.request.uri \-e http.user\_agent | head \-50  
Конкретные URL и User-Agent — инструментарий атакующего часто светится здесь.

tshark \-r capture.pcap \-Y "tls.handshake.type \== 1" \-T fields \-e ip.src \-e ip.dst \-e tls.handshake.extensions\_server\_name | sort \-u  
SNI из TLS ClientHello — видны C2-домены даже в зашифрованном трафике.

tshark \-r capture.pcap \--export-objects http,./exported/ 2\>/dev/null  
file ./exported/\*

find . \-maxdepth 1 \-empty \-type f \-delete

foremost capture.pcap   
Восстанавливает с оригинальными именами

Извлечь все HTTP-объекты на диск и определить их тип — дропперы, шеллы, zip-архивы.

5 — Учётные данные и секреты   
Утекло ли что-то ценное?

tshark \-r capture.pcap \-Y ftp \-T fields \-e ip.src \-e ftp.request.command \-e ftp.request.arg  
FTP в открытом виде — логины, пароли и передаваемые файлы.

tshark \-r capture.pcap \-Y "http.authorization" \-T fields \-e ip.src \-e http.authorization  
HTTP Basic Auth — base64 от логина:пароля в открытом виде.

tshark \-r capture.pcap \-Y "smtp || pop || imap" \-T fields \-e ip.src \-e ip.dst \-e \_ws.col.Info | head \-50  
Почтовые протоколы без шифрования — содержимое писем и credentials.

6 — Временна́я шкала   
Когда что произошло?

tshark \-r capture.pcap \-T fields \-e frame.time \-e ip.src \-e ip.dst \-e \_ws.col.Protocol \-e \_ws.col.Info \-Y "ip.src \== \<SUSPECT\_IP\>" | head \-100  
Детальная хронология всех действий подозреваемого хоста.

tshark \-r capture.pcap \-q \-z follow,tcp,ascii,\<stream\_id\>  
Полная реконструкция TCP-потока в ASCII — шеллы, команды, ответы C2.

A — Расшифровка TLS Снять шифрование, если есть ключи

SSLKEYLOGFILE  
Если дамп снят с хоста жертвы — проверь наличие файла с сессионными ключами (браузеры, curl, Python умеют его писать). Грузится прямо в Wireshark: Edit → Preferences → TLS → Pre-Master Secret log.  
tshark \-r cap.pcap \-o tls.keylog\_file:keys.log

JA3 / JA3S fingerprint  
Даже без расшифровки — fingerprint TLS ClientHello идентифицирует конкретный инструмент (Cobalt Strike, Metasploit, curl). Сравнивается с базами ja3er.com.  
tshark \-Y tls.handshake.type==1 \-T fields \-e tls.handshake.ja3

Анализ сертификата  
Самоподписанные сертификаты, подозрительный Issuer/Subject, срок жизни 1 день — характерно для C2-инфраструктуры (Cobalt Strike дефолтный cert хорошо известен).  
tshark \-Y tls.handshake.type==11 \-T fields \-e tls.handshake.certificate

HASSH (SSH fingerprint)  
Аналог JA3 для SSH — fingerprint алгоритмов согласования ключей. Позволяет различить легитимный OpenSSH от кастомных имплантов.  
zeek / arkime / python-hassh

B — Поведенческий анализ Паттерны, а не отдельные пакеты  
Beaconing detection  
C2-агенты «звонят домой» с регулярными интервалами. Строй гистограмму временны́х дельт между соединениями к одному IP/домену. Слишком равномерный интервал — почти наверняка beacon.  
tshark → csv → python (pandas \+ matplotlib)

Entropy DNS-запросов  
Длинные, высокоэнтропийные субдомены (base64, hex) — признак DNS tunneling (dnscat2, iodine) или DGA-малвари. Считай энтропию Шеннона по полю qry.name.  
python: math.log2 \+ collections.Counter  
Long connections  
Сессии длиной десятки минут с периодической активностью — интерактивный шелл или RAT. Ищи TCP-потоки с малым числом пакетов, но большим временны́м окном.  
tshark \-z conv,tcp | awk '{print $1,$NF}' | sort \-k2 \-rn

Data size anomaly  
Большой исходящий трафик на нетипичный внешний IP — потенциальная эксфильтрация. Сравни объёмы tx vs rx для каждой пары: нормальный browsing асимметричен (rx \>\> tx).  
tshark \-z conv,ip | awk '$6 \> $8'

C — Обогащение данных IP и хэши против внешних баз  
IP reputation  
Прогони уникальные внешние IP через VirusTotal, AbuseIPDB, Shodan, ip-api.com. Хостинг в Bulletproof AS, Tor exit node, или совпадение с известной C2 — подтверждает гипотезу.  
tshark \-T fields \-e ip.dst | sort \-u | xargs \-I{} curl ...

Хэши извлечённых файлов  
После foremost/tshark \--export-objects посчитай sha256 каждого файла и проверь в VT, MalwareBazaar, Hybrid Analysis. Совпадение с известным малварем закрывает вопрос об атрибуции.  
sha256sum exported/\* | awk '{print $1}' | vt search

Passive DNS / WHOIS  
Домены из DNS-запросов проверяй на возраст (свежезарегистрированный домен — красный флаг), резолвинг, смену NS. VirusTotal, SecurityTrails, PassiveDNS.  
whois \+ dig \+ SecurityTrails API

ASN / геолокация  
Трафик в страны, где бизнес не работает, или в AS провайдеров, известных как хостинг C2 — немедленный приоритет для расследования.  
mmdbinspect / geoiplookup / ip-api.com

D — Специализированные инструменты Когда tshark упирается в потолок

Zeek  
Генерирует структурированные логи: conn.log, http.log, dns.log, ssl.log, files.log, x509.log. Намного удобнее для временно́й корреляции и написания детектов. Стандарт в SOC.  
zeek \-r capture.pcap local

Suricata / Snort  
Прогони дамп через IDS с актуальными сигнатурами (ET Open, ET Pro). Даст прямые алерты с CVE и классификацией атаки — быстрейший способ поставить диагноз.  
suricata \-r capture.pcap \-l ./logs/

NetworkMiner  
GUI-инструмент: автоматически реконструирует сессии, извлекает файлы, credentials, картинки, сертификаты. Удобен для быстрого "что передавалось" без командной строки.  
NetworkMiner.exe / mono NetworkMiner.exe

Arkime (Moloch)  
Загружаешь PCAP — получаешь полноценный поиск по всем полям, визуализацию сессий, экспорт. Незаменим для больших дампов (\>1 GB) где tshark неудобен.  
capture \-r capture.pcap \+ web UI  
---

E — Итоговая корреляция Связать всё в единую картину  
Таймлайн инцидента  
Сведи все находки в хронологию: первый контакт → разведка → эксплойт → закрепление → lateral movement → эксфильтрация. Для каждого события — timestamp, src IP, dst IP, протокол, артефакт (URL / файл / команда). Это и есть финальный отчёт форензики.  
Атрибуция к TTPs (MITRE ATT\&CK)  
Каждый обнаруженный паттерн (beaconing, DNS tunneling, credential dumping по сети) маппируй на технику ATT\&CK. Это помогает классифицировать угрозу, сравнить с известными группами и написать детекты.  

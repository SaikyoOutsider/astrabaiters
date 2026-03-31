Памятка: https://vir-lab.ru/as/table2.html 
VMware (ссылка рабочая): 
https://www.comss.ru/page.php?id=2110&ysclid=mn8uigyb8f856711453 


Конвертация VDI-VMDK (для autopsy):
В VirtualBox
Файл-Инструменты-Менеджер вирутальных носителей-Добавить vdi образ-копировать-VMDK

Чтобы вмонтировать в kali:
Вставить в Контроллер SATA через VirtualBox;
lsblk - посмотреть диски
sudo fdisk -l - посмотреть диски
sudo mkdir /mnt/vdi
sudo mount /dev/sdb1 /mnt/vdi - обычно sdb1

LINUX
Расследование:
Bash history:
cat /mnt/vdi/root/.bash_history
cat /mnt/vdi/home/*/.bash_history

Основная папка с логами:
cd /mnt/vdi/var/log
Для временных отметок:
syslog
auth.log

Кто логинился (не совсем понятно расписано):
wtmp
btmp


Далее много ложных срабатываний:
Упоминания IP-адресов:
grep -RHE '([0-9]{1,3}\.){3}[0-9]{1,3}' /mnt/vdi/var/log 2>/dev/null
Сетевые команды
grep -R "wget\|curl\|bash -i" /mnt/vdi 2>/dev/null
Reverse shell
grep -R "socket\|connect\|/dev/tcp" /mnt/vdi 2>/dev/null
Подозрительные файлы ?
find /mnt/vdi -type f -perm -4000 2>/dev/null
Автозапуск:
ls /mnt/vdi/etc/cron.*
cat var/spool/cron/crontabs/* 
cat etc/crontab
	systemd:
	ls /mnt/vdi/etc/systemd/system
find . -type f -printf '%TY-%Tm-%Td %TT %p\n' | sort -r | head -n 20
./igorivanovich/.nr_plugin/logs/Log20250324_nr_server.log

История браузера (на примере Chromium, остальные лежат в той же директории)
/mnt/vdi/home/USERNAME/.config/chromium/Default
sqlite3 History
.headers on - для удобной отрисовки
.mode column - для удобной отрисовки
.tables - показать таблицы
select * from urls; - история
downloads - загрузки
Следы взаимодействия с USB:
grep -i usb /mnt/vdi/var/log/syslog
grep -i usb /mnt/vdi/var/log/kern.log
grep -i usb /mnt/vdi/var/log/dmesg*
journalctl | grep -i usb
journalctl -k | grep -i usb

Удаленные файлы:
ls -la /mnt/vdi/home/*/.local/share/Trash/files/
cat /mnt/vdi/home/*/.local/share/Trash/info/*.trashinfo

	SQLite-кеши приложений:
	Могут лежать здесь (там же встречаются удаленные файлы из предыдущего пункта):
	/mnt/vdi/home/USERNAME/.local/share
	Старые пути к файлам/директориям:
	find /mnt/vdi -name "*.desktop" -o -name ".directory" 2>/dev/null
Настройки для быстрого AutoPsy:
	Посмотреть временные файлы в /tmp

	Поиск точки входа:
	Поиск файла во входящей почте:
grep -rl "3A9BJ7EHUE.desktop" /mnt/vdi/home/igorivanovich/.cache/evolution/mail/
✅ Recent Activity ← №1 приоритет (браузеры, недавние файлы, запущенные программы, USB)
✅ Hash Lookup (NSRL + свои bad-хэши — сразу покажет malware)
✅ File Type Identification
✅ Extension Mismatch Detector (переименованные exe → jpg и т.п.)
✅ Interesting Files Identifier (автозагрузка, подозрительные места)
✅ Keyword Search (добавь свои IOC после — строки, IP, хэши)
✅ Embedded File Extractor (вытаскивает из zip/office — полезно)

Смотреть ВСЕ файлы, абсолютно все. Если файлы упоминаются в скрипте, их тоже надо смотреть и указывать в отчете.













WINDOWS
	Основной источник логов - журналы:
	Windows/System32/winevt/Logs/
	Формат evtx можно открывать утилитой evtxexport
	Основные журналы:
	Security.evtx - логи авторизации
	System.evtx - загрузки, драйвера, перезагрузки
	Application.evtx - логи приложений
	
	Логи PowerShell:
Users/USERNAME/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline
	
	Список процессов:
	Windows/Prefetch

	Автозагрузка:
Users/USERNAME/AppData/Roaming/Microsoft/Windows/’Start Menu’/Programs/Startup

	Недавние файлы:
/mnt/vdi/Users/USERNAME/AppData/Roaming/Microsoft/Windows/Recent/

Jump-листа ():
/mnt/vdi/Users/USERNAME/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations

	Истории браузеров:
Users/USERNAME/AppData/Local/BROWSER…
Пример для Yandex Browser:
Users/Ivan/AppData/Local/Yandex/YandexBrowser/’User Data’/Default
	И дальше sqlite3 History аналогично с linux-образом
	
	


regripper - логи и системные журналы
mkdir -p ~/win_analysis

# 1. Службы (WinDefend, firewall, SMB1 и т.д.)
regripper -r SYSTEM -p services > ~/win_analysis/01_services.txt

# 2. RDP / Terminal Server (самое важное!)
regripper -r SYSTEM -p terminalserver > ~/win_analysis/02_rdp.txt

# 3. Пользователи и группы (Remote Desktop Users + Administrators)
regripper -r SAM -p samparse > ~/win_analysis/03_users_groups.txt

# 4. Defender и политики
regripper -r SOFTWARE -p defender > ~/win_analysis/04_defender.txt

# 5. Автозагрузка (Run/RunOnce)
regripper -r SOFTWARE -p run > ~/win_analysis/05_autorun.txt

Ещё одна удобная штука
sudo apt install libhivex-bin -y   # если ещё не установлено
CONFIG="/mnt/vdi/Windows/System32/config"
echo "=== 1. ТЕКУЩИЙ ControlSet (важно!) ==="
hivexget $CONFIG/SYSTEM '\Select' Current
echo "=== 2. RDP включён? (fDenyTSConnections = 0 — опасно!) ==="
hivexget $CONFIG/SYSTEM '\ControlSet001\Control\Terminal Server' fDenyTSConnections 2>/dev/null || echo "Не найдено в 001"
hivexget $CONFIG/SYSTEM '\ControlSet002\Control\Terminal Server' fDenyTSConnections 2>/dev/null || echo "Не найдено в 002"
echo "=== 3. WinDefend отключён? (Start = 4 — отключена) ==="
hivexget $CONFIG/SYSTEM '\ControlSet001\Services\WinDefend' Start 2>/dev/null || echo "Не найдено"
hivexget $CONFIG/SYSTEM '\ControlSet002\Services\WinDefend' Start 2>/dev/null || echo "Не найдено"
echo "=== 4. SMB1 включён? ==="
hivexget $CONFIG/SYSTEM '\ControlSet001\Services\LanmanServer\Parameters' SMB1 2>/dev/null || echo "Не найдено"
echo "=== 5. Firewall полностью открыт? (ищем allowinbound,allowoutbound) ==="
hivexget $CONFIG/SYSTEM '\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' EnableFirewall 2>/dev/null || echo "Не найдено"
stat /mnt/vdi/Users/Ivan
Выгрузка авторана:
regripper -r /mnt/vdi/Windows/System32/config/SOFTWARE -p run > ~/win_analysis/autorun.txt


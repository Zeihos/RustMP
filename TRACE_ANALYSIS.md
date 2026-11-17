# RUSTMP: анализ сетевых захватов SA-MP/open.mp

Версия 0.2.0-alpha.16. Это офлайн-анализатор протокольных метаданных, а НЕ самостоятельный клиент GTA и НЕ доказательство полной совместимости RakNet.

## Использование

Для анализа UDP-пакетов из Wireshark, сохранённых в классический формат PCAP (.pcap):

    cargo run --locked -p rustmp-protocol --bin rustmp-trace -- capture.pcap --port 7777

IP-адреса скрыты по умолчанию. Чтобы явно показать IP и порты:

    cargo run --locked -p rustmp-protocol --bin rustmp-trace -- capture.pcap --port 7777 --show-endpoints

Команда показывает номер записи, время, порты, длину UDP, предполагаемый тип SA-MP Query или RakNet offline, число диапазонов ACK, количество frames, sequence/reliability/order/split первого кадра. Имена, пароли, токены, произвольный payload НЕ печатаются.

Файлы PCAPNG пока не поддерживаются напрямую. В Wireshark выберите File > Save As и классический формат pcap; альтернативно в терминале:

    tshark -r capture.pcapng -F pcap -w capture.pcap

## Поддерживаемые форматы

- Classic PCAP v2.4: little/big endian, microsecond/nanosecond timestamps
- Ethernet (LINKTYPE 1) с максимум двумя VLAN-тегами; RAW IPv4 (101)
- BSD loopback (0), Linux cooked v1 (113) и v2 (276), только IPv4/UDP
- SA-MP Query, ограниченные offline-пакеты SA-MP/open.mp и legacy RakNet frames, распознаваемые текущим кодеком

НЕ поддерживаются: pcapng, IPv6, сборка фрагментов IP, шифрование, декодирование игровых RPC, все вариации RakNet, проверка IP/UDP checksum и подтверждение аутентичности пакета. Классификация пакетов эвристическая: некоторые неизвестные сообщения могут совпадать по первым байтам.

## Ограничения и приватность

- Максимум 32 МиБ на файл; 256 КиБ на запись; 65 536 записей и 32 768 UDP-событий
- IP-фрагменты пропускаются (не пытаемся декодировать неполные UDP-пакеты)
- Публичная структура отчёта содержит IP-адреса и порты, но НЕ содержит raw payload. Консоль скрывает IP по умолчанию
- САМ файл .pcap может содержать секреты и личные данные, даже если эта программа их не выводит. Не размещайте неочищенные дампы в публичном GitHub
- Анализатор не подключается к живому UDP-серверу и не разрешает подключение настоящих игроков

## Проверка

    cargo check --locked --workspace --all-targets
    cargo test --locked --workspace
    cargo run --locked -p rustmp-protocol --bin rustmp-trace -- --help

Тесты используют СИНТЕТИЧЕСКИЕ PCAP в памяти или временных файлах. Реальных захватов оригинальных клиентов в репозитории ещё нет. Следующий этап — собственный клиентский дамп и сверка каждого поля с исходниками RakNet.

Формат: https://wiki.wireshark.org/Development/LibpcapFileFormat
Ethernet: https://wiki.wireshark.org/Ethernet

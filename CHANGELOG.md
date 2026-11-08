# Changes

## 0.2.0-alpha.1 — 2026-11-08

- Новый `omp-transport`: разбор 3-байтового offline connect от legacy RakNet, 2-байтовый ответ и 5-байтовый ping/pong.
- Общий UDP-порт для query и RakNet offline.
- Ограничение количества непроверенных сессий, per-IP лимиты, 10-секундный timeout, защита от неограниченного роста таблицы IP.
- Тесты: корректные/повреждённые/повторные пакеты, ограничение слотов, таймаут, rate limit и loopback UDP.
- Тестовый клиент `offline_probe` и `test-windows.bat`.
- **Геймплей и RakNet reliability всё ещё отсутствуют.**

## 0.1.0 — 2026-11-08

- Первые крейты: query, core, server, конфигурация, пулы и тесты.

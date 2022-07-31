# Lab_2
Лабораторная работа No 2. Реализация NetFlow-сенсора

## Описание

Сенсор scanflowd предназначен для сбора и отправки сетевой статистики по протоколу NetFlow v.9

Сенсор формирует поток по следующим общим критериям пакетов:

1. протокол
2. тип обслуживания (IPv4)
3. адрес источника
4. адрес назначения
5. порт источника или тип ICMP
6. порт назначения или код ICMP

Порт сенсора: 9994

В статистике потоков содержется следующая информация:

1. суммарное число байт
2. суммарное число пакетов
3. время первого пакета
4. время последнего пакета

Если поток протокола TCP, то все флаги всех пакетов суммируются

Данные последнего пакета:

5. MAC-адрес источника
6. MAC-адрес назначения
7. ID IPv4

## Сборка

Для сборки программ вам потребуется пакет GNU GCC.
В принципе, все что нужно, это:
1. Скачать средства сборки: `sudo apr-get install gcc`
2. Перейти в директорию с Makefile и запустить make `make install`

Чтобы в текущей директории были созданы исполняемые файлы, исплользуйте `make all`

## Запуск

Для запуска программы необходимы права суперпользователя. Синопсис:

`sudo scanerflowd [interface name (enp*s* ...)] [ip коллектора]:[порт]`

Чтобы узнать доступные сетевые интерфейсы, можно воспользоваться командой `networkctl`

Для тестирования работоспособности программы можно использовать утилиту nfcapd как коллектор NetFlow

Запуск коллектора:

`sudo nfcapd -l ~/stat/ -b 127.0.0.1`

Запуск сенсора:

`sudo ./scanflowd [interface name (enp*s* ...)] 127.0.0.1:9995`

## Авторство и лицензия

Разработчик: Филатов И.А.
e-mail: f2000_99@mail.ru

Лицензия GNU GPL v.3

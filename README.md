# esd

[English](#Eng) | [Russian](#Ru)<a id=Eng></a>
# Express Server Diagnostics

* Requires no installation
* Performs diagnostics on a Linux server across a wide range of parameters
* Groups log entries to give a broader overview at a glance
* Doesn't replace your knowledge or experience – just saves your time

## Usage:

Simply run this command on the server:

```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | tail -1 | grep -q esdfulldwnldok && echo "$content" | bash || echo "Probably failed download. Will not be executed."; }
```

This command checks if the download is successful before executing the script.

Additionally, there’s a stricter verification option using md5 - the command:

```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | md5sum | grep -q 2c77a4895237d582f5146a7bec453f61 && echo "$content" | bash || echo "MD5 checksum mismatch. Will not be executed."; }
```
The downside of this approach is the need to update the saved md5-hash in the command whenever the script is updated.

## Additional Information:

* The script will check if a control panel is installed on the server and, if possible, generate a URL for access.
* It will check for hard drives, smartctl availability, and check how long ago each drive was last tested.
* It will check other important server health metrics such as free disk space, inodes, memory, etc.
* It will display messages about any detected potential issues.
* It will read most of the major server logs, filter the entries, keeping only messages that likely require attention, and group similar records.
* A single script cannot account for all the nuances of every server setup, so it is not recommended to fully rely on the results of this diagnostics.
* Memory usage by users may display inflated values since shared memory used by processes cannot be accurately excluded in the calculation.

[English](#Eng) | [Russian](#Ru)<a id=Ru></a>
# Express Server Diagnostics

* Не требует установки
* Выполняет диагностику linux-сервера по множеству параметров
* Группирует записи из логов, чтобы одним взглядом охватить больше
* Не заменяет ваши мозги и знания - просто экономит ваше время

## Использование:

Просто выполните на сервере эту команду:

```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | tail -1 | grep -q esdfulldwnldok && echo "$content" | bash || echo "Probably failed download. Will not be executed."; }
```

В данной команде осуществляется проверка успешной загрузки, перед тем, как будет запущено непосредственно выполнение скрипта.

Также, есть более строгий вариант проверки с использованием md5 - команда:

```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | md5sum | grep -q 2c77a4895237d582f5146a7bec453f61 && echo "$content" | bash || echo "MD5 checksum mismatch. Will not be executed."; }
```

Минусом данного подхода является необходимость обновлять md5-hash в сохраненной команде при каждом обновлении скрипта.

## Дополнительная информация:

* Скрипт проверит наличие установленной панели управления на сервере и при возможности сгенерирует URL для входа.
* Проверит наличие жестких дисков, наличие и показатели smartctl, в том числе, как давно выполнялась последняя проверка каждого диска.
* Проверит другие важные показатети состояния сервера, в том числе, свободное дисковое пространство и inodes, оперативную память и т.д.
* Выведет сообщения обо всех обнаруженных потенциальных проблемах.
* Прочитает большинство основных логов сервера, отфильтрует записи, оставив лишь сообщения, которые вероятно могут потребовать внимания и сгруппирует схожие записи.
* В одном скрипте нельзя охватить все нюансы работы всех возможных вариаций серверов, поэтому не рекомендуется всецело полагаться на результаты данной диагностики.
* Информация об использовании оперативной памяти пользователями может отображать завышенные значения, поскольку при подсчете использования памяти процессами невозможно учесть и исключить совместно-используемую разделяемую память.

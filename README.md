# esd

# Express Server Diagnostics

* Не требует установки
* Выполняет диагностику linux-сервера по множеству параметров
* Группирует записи из логов, чтобы одним взглядом охватить больше
* Не заменяет ваши мозги и знания - просто экономит ваше время

## Использование:
```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | md5sum | grep -q e1d310d82c6204833f4ede1164115146 && echo "$content" | bash || echo "MD5 checksum mismatch. Will not be executed."; }
```

### English

# Express Server Diagnostics

* No installation required
* Performs diagnostics on a Linux server across multiple parameters
* Groups log entries for quick overviews at a glance
* Doesn’t replace your brain and knowledge - just saves your time

## Usage:

```
curl -H "Cache-Control: no-cache" -s https://raw.githubusercontent.com/simon-project/esd/refs/heads/main/esd.sh  | { content=$(cat); echo "$content" | md5sum | grep -q e1d310d82c6204833f4ede1164115146 && echo "$content" | bash || echo "MD5 checksum mismatch. Will not be executed."; }
```


# WSCT GlobalPlatform Command Line

wsct-gp is a command line tool to interact with GlobalPlatform cards.

The current status of this tool is *work in progress*.

## General commands

### List available readers

Allows to list available readers.

```bash
wsct-gp list-readers
```

## GlobalPlatform commands

### Check the default card manager

Allows to check the default card manager.

```bash
wsct-gp card-manager
```

### List applications

Allows to list applications installed on the card.

```bash
wsct-gp list-applications
```
- [ ] SCP01
- [x] SCP02
- [x] Default keys
- [ ] Specific keys


### DELETE application

Deletes an application installed on the card.

```bash
wsct-gp delete-application --aid <aid>
```

### INSTALL [for install and make selectable]

```bash
wsct-gp install --aid <aid> --aid-exec <executable-aid> --cap <path-to-cap-file>
```

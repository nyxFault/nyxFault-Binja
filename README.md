# nyxFault-Binja

[![GitHub license](https://img.shields.io/github/license/nyxFault/nyxFault-Binja.svg?style=for-the-badge)](https://github.com/nyxFault/nyxFault-Binja/blob/main/LICENSE)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg?style=for-the-badge)
[![Last Commit](https://img.shields.io/github/last-commit/nyxFault/nyxFault-Binja.svg?style=for-the-badge)](https://github.com/nyxFault/nyxFault-Binja)
![Binary Ninja](https://img.shields.io/badge/Binary%20Ninja-Plugin-blue?style=for-the-badge)


A collection of Binary Ninja plugins designed to streamline and enhance your reverse-engineering workflow. These tools simplify common tasks, automate repetitive actions, and introduce new capabilities that extend Binary Ninja’s functionality. I built these plugins while learning Binary Ninja and I personally liked its Python API very much and decided to develop some plugins to gain hands-on experience. I have developed few basic plugins.

## Installation

Clone this repository into your Binary Ninja **plugins** directory.

### Windows

```bash
cd "%APPDATA%\Binary Ninja\plugins\"
git clone https://github.com/nyxFault/nyxFault-Binja
```
This will produce a path similar to:

```bash
C:\Users\<yourname>\AppData\Roaming\Binary Ninja\plugins\nyxFault-Binja
```

### Linux

```bash
cd ~/.binaryninja/plugins/
git clone https://github.com/nyxFault/nyxFault-Binja
```

After cloning, restart Binary Ninja and the plugins should load automatically.

To verify that the plugin loaded successfully, check the Log panel.
You should see messages similar to:

```txt
[ScriptingProvider] [nyxfault_plugins] Plugin loaded.
[PythonPlugin] Loaded python3 plugin 'nyxFault-Binja'
```

### Usage

You can access the plugins in two ways:

#### 1. Through the Plugins Menu

Navigate to:

**Plugins → nyxFault-Binja**

It should look like this:

![Plugin](https://github.com/nyxFault/nyxFault-Binja/blob/main/image.png?raw=true)

#### 2. Through the Command Palette

Press **Ctrl + P** to open the Command Palette,
type _nyxFault_, and select the desired plugin from the filtered list.

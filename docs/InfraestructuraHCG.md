# MAPA DE INFRAESTRUCTURA CENTRALIZADO (MIC)
## HOSPITAL CIVIL DE GUADALAJARA (HCG) / OPD-HCG

---

**Clasificación:** CONFIDENCIAL / RED TEAM OPERATIONS  
**Versión:** 4.0 - CONSOLIDACIÓN FINAL INTEGRADA  
**Timestamp de Generación:** 2026-03-04  
**Marco de Referencia:** PTES / MITRE ATT&CK / Cyber Kill Chain / NIST SP 800-115  
**Sistema:** Infrastructure Integrity Auditor

---

## ÍNDICE

1. [Resumen de Activos](#1-resumen-de-activos)
2. [Topología de Red](#2-topología-de-red)
3. [Configuración de Servidores/Nodos](#3-configuración-de-servidoresnodos)
4. [Logs y Eventos Técnicos](#4-logs-y-eventos-técnicos)
5. [Dependencias y Servicios](#5-dependencias-y-servicios)
6. [Credenciales/Seguridad](#6-credencialeseguridad)
7. [Vulnerabilidades CVE](#7-vulnerabilidades-cve)
8. [Matriz MITRE ATT&CK](#8-matriz-mitre-attck)
9. [Conflictos de Datos](#9-conflictos-de-datos)

---

## [SECCIÓN 1: RESUMEN DE ACTIVOS]

### 1.1 Métricas Globales Consolidadas

| Categoría | Cantidad |
|-----------|----------|
| Archivos procesados | 8 |
| Activos críticos identificados | 20+ |
| Direcciones IP documentadas | 150+ |
| Servidores internos documentados | 14 |
| Hosts activos en subred 10.1.7.0/24 | 74 |
| Interfaces de red | 7 |
| Usuarios locales | 10 |
| Grupos de seguridad | 14 |
| Credenciales almacenadas | 12 |
| Procesos monitoreados | 5 |
| Tareas programadas no-Microsoft | 15 |
| Impresoras configuradas | 21 |
| Reglas firewall inbound | 61+ |
| Parches instalados | 4 |
| Servicios HCG | 14 |
| Conexiones TCP activas | 84 |
| Entradas ARP | 95 |
| Registros DNS | 68 |
| Vulnerabilidades CVE catalogadas | 10 |
| Redes Wi-Fi detectadas | 10 SSIDs |

### 1.2 EQUIPO PRINCIPAL ANALIZADO (Host Origen)

| Parámetro | Valor Exacto |
|-----------|--------------|
| **Nombre de Máquina** | `10524DIVSERADMI` |
| **FQDN** | `10524divseradmin.mshome.net` |
| **Machine ID** | `{65CD7792-CFEE-451D-850D-29F9187D6CA3}` |
| **Sistema Operativo** | Windows 11 Pro 64-bit |
| **Build** | `10.0.26200` (26100.ge_release.240331-1435) / `10.0.26200.7922` |
| **HAL** | `10.0.26100.1` |
| **Idioma** | Spanish (Regional Setting: Spanish) |
| **Tipo de Dominio** | `<equipo local>` |
| **Nombre de Dominio Local** | `10524DIVSERADMI` / `DIVSERADMIN` |
| **Dominio de Login** | MicrosoftAccount |
| **Logon Server** | `\\10524DIVSERADMI` |
| **Computer SID Domain** | `S-1-5-21-3216482593-212876407-1992140904` |
| **Configuración del sistema** | Estación de trabajo independiente |
| **Directorio Windows** | `C:\WINDOWS` |
| **DirectX Version** | DirectX 12 |

### 1.3 HARDWARE - FABRICANTE

| Parámetro | Valor Exacto |
|-----------|--------------|
| **Fabricante del Sistema** | `LENOVO` |
| **Modelo del Sistema** | `ThinkCentre M720s` |
| **ID Modelo** | `10SUSP0F00` |
| **BIOS** | `M1UKT77A` (type: UEFI, fecha: 10/04/2024) |
| **SMBIOS** | 3.2 |
| **Arquitectura** | x64-based PC |

### 1.4 PROCESADOR

| Parámetro | Valor Exacto |
|-----------|--------------|
| **Modelo** | Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz |
| **Núcleos** | 8 CPUs |
| **Frecuencia** | ~3.0GHz |
| **Arquitectura** | x64 |

### 1.5 MEMORIA

| Parámetro | Valor Exacto |
|-----------|--------------|
| **RAM Total** | 8192MB RAM |
| **RAM Disponible** | 8062MB RAM |
| **Page File Usado** | 11077MB |
| **Page File Disponible** | 9783MB |

### 1.6 ALMACENAMIENTO

| Unidad | Modelo | Espacio Total | Espacio Libre | Sistema de Archivos | Controlador |
|--------|--------|---------------|---------------|---------------------|-------------|
| C: | WDC PC SN730 SDBQNTY-256G-1001 | 242.9 GB | 62.1 GB | NTFS | NVM Express estándar (stornvme.sys) |
| D: | PLDS DVD-RW DA8AESH | [N/A] | [N/A] | Óptico | cdrom.sys |

### 1.7 TARJETA GRÁFICA

| Parámetro | Valor |
|-----------|-------|
| **GPU** | Intel(R) UHD Graphics 630 |
| **Chip Type** | Intel(R) UHD Graphics Family |
| **DAC type** | Internal |
| **Device Type** | Full Device (POST) |
| **Device Key** | `Enum\PCI\VEN_8086&DEV_3E98&SUBSYS_312A17AA&REV_02` |
| **Vendor ID** | `0x8086` |
| **Device ID** | `0x3E98` |
| **SubSys ID** | `0x312A17AA` |
| **Revision ID** | `0x0002` |
| **Display Memory** | 4158 MB |
| **Dedicated Memory** | 128 MB |
| **Shared Memory** | 4030 MB |
| **Current Mode** | 1440 x 900 (32 bit) (60Hz) |
| **HDR Support** | Not Supported |
| **Display Topology** | Internal |
| **Driver Version** | 31.0.101.2115 |
| **Driver Date** | 15/11/2022 06:00:00 p. m. |
| **Driver Model** | WDDM 3.1 |
| **Feature Levels** | 12_1, 12_0, 11_1, 11_0, 10_1, 10_0, 9_3, 9_2, 9_1, 1_0_CORE |
| **WHQL Logo'd** | Yes |
| **Display Color Space** | DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709 |
| **Color Primaries** | Red(0.653320,0.336914), Green(0.322266,0.610352), Blue(0.151367,0.064453), White Point(0.313477,0.329102) |
| **Display Luminance** | Min=0.500000, Max=270.000000, MaxFullFrame=270.000000 |
| **DDI Version** | 12 |
| **Adapter Attributes** | HARDWARE_TYPE_GPU, D3D12_GRAPHICS, D3D12_CORE_COMPUTE, D3D12_GENERIC_ML, D3D12_GENERIC_MEDIA |

### 1.8 MONITOR

| Parámetro | Valor |
|-----------|-------|
| **Nombre** | Generic PnP Monitor |
| **Modelo** | LEN E2054A |
| **Monitor ID** | LEN60DF |
| **Native Mode** | 1440 x 900(p) (59.887Hz) |
| **Output Type** | Displayport External |
| **HDR Support** | Not Supported |
| **Pixel Format** | DISPLAYCONFIG_PIXELFORMAT_32BPP |
| **Advanced Color** | Not Supported |
| **WCG** | Wcg Not Supported |
| **Active Color Mode** | DISPLAYCONFIG_ADVANCED_COLOR_MODE_SDR |

### 1.9 AUDIO

| Parámetro | Valor |
|-----------|-------|
| **Dispositivo** | Speakers (Realtek(R) Audio) |
| **Hardware ID** | `HDAUDIO\FUNC_01&VEN_10EC&DEV_0235&SUBSYS_17AA312A&REV_1000` |
| **Driver** | `RTKVHD64.sys` v6.0.9279.1 |
| **Driver Date** | 06/12/2021 06:00:00 p. m. |
| **Driver Size** | 6569528 bytes |
| **Driver Provider** | Realtek Semiconductor Corp. |
| **WHQL Logo'd** | Yes |
| **HW Accel Level** | Emulation Only |
| **Cap Flags** | 0xF1F |
| **Min/Max Sample Rate** | 100, 200000 |

### 1.10 PERIFÉRICOS

| Dispositivo | Vendor ID | Product ID | Estado |
|-------------|-----------|------------|--------|
| Mouse | - | - | Attached (1) |
| Teclado | - | - | Attached (1) |
| Tripp Lite UPS | 0x09AE | 0x2010 | Attached (Controller ID: 0x0) |
| Lenovo Calliope USB Keyboard | 0x17EF | 0x608C | Attached (2 instancias) |
| USB Input Device (Mouse) | 0x17EF | 0x608D | Attached |
| USB Composite Device | 0x17EF | 0x608C | Attached |

### 1.11 Dominios Identificados

| Dominio | Tipo | Contexto |
|---------|------|----------|
| hcg.gob.mx | Principal | Portal institucional |
| opd-hcg.org | Dominio AD | Controlador de dominio |
| opdhcg.net | Correo | Servidor de correo |
| hcfaa.com | Tercerizado | Sin hosts activos identificados |

---

## [SECCIÓN 2: TOPOLOGÍA DE RED]

### 2.1 IDENTIFICACIÓN ORGANIZACIONAL

| Campo | Valor |
|-------|-------|
| **Organización** | Hospital Civil de Guadalajara (HCG) / OPD-HCG |
| **Dominios Auditados** | hcg.gob.mx, hcfaa.com, opd-hcg.org, DIVSERADMIN, lajun.hosting-mexico.net |
| **Total de Hosts Auditados** | 17+ |
| **Documentos Fuente Analizados** | 8 |

### 2.2 Segmentos de Red Identificados

| Segmento | Rango CIDR | Propósito | Gateway |
|----------|------------|-----------|---------|
| WAN/Externa | 201.131.x.x | Portal público | N/D |
| Hosting Externo | 216.245.192.0/19 | Servicios externos WHM/cPanel | N/D |
| OT (Operacional) | 192.168.1.0/24 | Dispositivos control hospitalario HVAC/ICS | N/D |
| IT Institucional | 10.254.0.0/16 | Servidores BD/Aplicaciones VLAN Gestión | 10.254.0.1 |
| IT Interno Principal | 10.1.7.0/24 | Workstations | 10.1.7.254 |
| VLAN Terminales | 10.2.0.0/16 | Terminales biométricas SIGMA/Morpho | N/D |
| VLAN Servicios | 10.2.1.0/24 | Servidores críticos DC, SIGMA, CBS | N/D |
| VLAN Especializada | 10.2.22.0/24 | Sistema PES OPD-HCG | N/D |
| VLAN Sincronización | 10.2.61.0/24 | Sincronización nodos | N/D |
| VLAN Virtualización | 10.1.61.0/24 | Sincronización virtual | N/D |
| Docker/WSL | 172.21.240.0/20 | Redes virtuales Default Switch | N/D |
| WSL/mshome | 172.27.16.0/20 | WSL | N/D |

### 2.3 MAPA DE DOMINIOS HCG

```
DOMINIO PRINCIPAL: hcg.gob.mx
├── www.hcg.gob.mx (External Target) - Web Pública
│   └── Apache 2.4.38 / PHP 7.1.26 / OpenSSL 1.0.2q
├── expediente.hcg.gob.mx (10.2.1.140) - Sistema de Expedientes
│   └── RDP:3389/TCP, SMB:445/TCP
├── sigma.hcg.gob.mx (10.2.1.139) - Infraestructura Biométrica
│   └── [ALTA SENSIBILIDAD - PHI/PII/Biometric Templates]
├── api-sigma.hcg.gob.mx (10.2.1.139) - API REST
├── empleado.hcg.gob.mx (10.2.1.140) - Portal Empleado
├── pah.hcg.gob.mx (10.2.1.140) - Portal PAH
├── intranet.hcg.gob.mx (10.2.1.140) - Intranet
├── cbs.hcg.gob.mx (10.2.1.141) - Servidor CBS
├── sah.hcg.gob.mx (10.2.1.141) - Servidor SAH
├── pp.hcg.gob.mx (10.2.1.141) - Servidor PP
├── certificados.hcg.gob.mx (10.2.1.165) - Certificados Digitales
├── sii.hcg.gob.mx (10.2.1.136) - Sistema Info Institucional
└── portal.hcg.gob.mx (10.2.1.12) - Portal Interno

DOMINIO SECUNDARIO: opd-hcg.org
├── 10.2.1.1 - Controlador de Dominio (LDAP/DNS)
│   └── LDAP:389/TCP, DNS:53/TCP
└── pesopd.opd-hcg.org (10.2.22.76)

DOMINIO CORREO: opdhcg.net
└── correo.opdhcg.net (10.2.1.46) - Servidor de Correo

DOMINIO TERCERIZADO: hcfaa.com
└── Sin hosts activos identificados en scan

HOSTING EXTERNO: lajun.hosting-mexico.net
└── 216.245.211.42 - cPanel/WHM Management
    └── Ports: 2082, 2083, 2086, 2087, 2095, 2096

INFRAESTRUCTURA DNS EXTERNA
└── b.rec.ns.udg.mx (148.202.3.5) - DNS Server
    └── Port: 53/UDP
```

### 2.4 MATRIZ DE SEGMENTACIÓN Y PERMEABILIDAD

| Zona Origen | Zona Destino | Permeabilidad | Controles Identificados | Riesgo |
|-------------|--------------|---------------|------------------------|--------|
| Internet | 10.2.1.0/24 | **ALTA** | Firewall perimetral (configuración desconocida) | CRÍTICO |
| Internet | 10.254.0.0/16 | **MEDIA** | VPN requerida (posible mal configuración) | ALTO |
| 10.254.x.x | 10.2.1.x | **ALTA** | Segmentación permeable, sin microsegmentación | CRÍTICO |
| 10.2.1.x | 10.254.x.x | **ALTA** | Comunicación bidireccional habilitada | ALTO |
| 10.2.1.140 | 10.2.1.139 | **ALTA** | SMB/RDP entre servidores críticos | CRÍTICO |

### 2.5 HOSTS INTERNOS - SEGMENTO 10.2.1.0/24 (CORE CRÍTICO)

| IP | Hostname | Zona | Puertos Abiertos | Servicios | Criticidad |
|----|----------|------|-----------------|-----------|------------|
| 10.2.1.1 | opd-hcg.org | Internal | 389/TCP, 53/TCP | LDAP, DNS | CRÍTICA |
| 10.2.1.7 | HCGINFMED | Internal | - | Servidor de Información Médica | ALTA |
| 10.2.1.11 | jim3 | Internal | - | [DATO_PENDIENTE_DE_CONFIRMACIÓN] | MEDIA |
| 10.2.1.12 | portal.hcg.gob.mx | Internal | 80/TCP, 443/TCP | Portal interno | MEDIA |
| 10.2.1.46 | correo.opdhcg.net | Internal | - | Servidor de correo | ALTA |
| 10.2.1.136 | sii.hcg.gob.mx | Internal | - | Sistema de Información Institucional | ALTA |
| 10.2.1.139 | sigma.hcg.gob.mx | Internal | 80/TCP, 443/TCP | Sigma Biometric Infrastructure | CRÍTICA |
| 10.2.1.140 | expediente.hcg.gob.mx | Internal | 3389/TCP, 445/TCP, 80/TCP, 443/TCP | RDP, SMB, Multi-app | CRÍTICA |
| 10.2.1.141 | cbs.hcg.gob.mx | Internal | 80/TCP, 443/TCP | CBS, SAH, PP | ALTA |
| 10.2.1.165 | certificados.hcg.gob.mx | Internal | - | Certificados Digitales | ALTA |
| 10.2.1.92 | SERVIDOR-SMB-01 | Internal | 445/TCP | Servidor de archivos SMB | ALTA |
| 10.2.61.17 | SYNHCGN | Internal | 3306/TCP | MySQL | ALTA |

### 2.6 HOSTS INTERNOS - SEGMENTO 10.254.0.0/16 (USUARIOS/WIFI)

| IP | Hostname | Zona | Puertos Abiertos | Servicios | Criticidad |
|----|----------|------|-----------------|-----------|------------|
| 10.254.0.1 | - | Internal | - | Default Gateway | ALTA |
| 10.254.3.193 | - | Internal | 8009/TCP | AJP13 | ALTA |
| 10.254.30.158 | - | Internal | 8009/TCP | AJP13 | ALTA |
| 10.254.81.81 | - | Internal | 7680/TCP | WUDO | MEDIA |
| 10.254.117.118 | redopdhcg Client | Internal | - | WiFi Client | ALTA |
| 10.254.185.35 | - | Internal | 8009/TCP | AJP13 | ALTA |
| 10.254.225.221 | - | Internal | 8009/TCP | AJP13 | ALTA |

### 2.7 HOSTS EXTERNOS

| IP | Hostname | Zona | Puertos Abiertos | Servicios | Criticidad |
|----|----------|------|-----------------|-----------|------------|
| 201.131.132.131 | hcg.gob.mx, www.hcg.gob.mx | External Target | 80/TCP, 443/TCP | Apache 2.4.38 / IIS 10.0 | CRÍTICA |
| 216.245.211.42 | lajun.hosting-mexico.net | External | 2082-2096/TCP | cPanel/WHM | ALTA |
| 148.202.3.5 | b.rec.ns.udg.mx | External | 53/UDP | DNS | MEDIA |
| 201.131.132.136 | - | Unknown | 21,22,80,443,3306,3389 | Filtered | MEDIA |
| 66.24.102.44 | - | External | 47808/UDP | Delta Controls (ICS) | CRÍTICA |
| 211.21.101.106 | ACTIVO-SURV-01 | External | 554/TCP, 137/UDP | Videovigilancia Nginx | ALTA |

```markdown
### 2.7 GRAFO DE DEPENDENCIAS

```
[ACTIVOS EXTERNOS]
==================

[hcg.gob.mx] --[DNS]--> [201.131.132.131]
[NS-hosting-mexico.net] --[DNS Management]--> [hcg.gob.mx]
[ACTIVO-WEB-01] --[Fuga NTLM/445]--> [Attacker Server]
[ACTIVO-WEB-01] --[Certificado SSL]--> [*.hcg.gob.mx (Expira: May 2026)]
[ACTIVO-WEB-01] --[Vectores Pivot/VLAN Operativa]--> [192.168.1.30]
[ACTIVO-WEB-01] --[HTTP/Headers]--> [Backend Apps/Internal Tomcat]
[ACTIVO-SURV-01] --[Protocolo BACnet]--> [ACTIVO-ICS-01]


[ACTIVOS INTERNOS]
==================

[10524DIVSERADMI] --[UDP/53 DNS]--> [10.2.1.1]
[10524DIVSERADMI] --[TCP/389 LDAP]--> [10.2.1.1]
[10524DIVSERADMI] --[TCP/445 SMB]--> [10.2.1.92]
[10524DIVSERADMI] --[TCP/3306 MySQL]--> [10.2.61.17]
[sigma.hcg.gob.mx] --[PTR]--> [10.2.1.139]
[expediente.hcg.gob.mx] --[A]--> [10.2.1.140]
[chromoting] --[TCP/Local]--> [Google Chrome Remote Desktop]


[ACTIVOS BIOMÉTRICOS]
=====================

[Activo ID-01] --[Docker Socket: /var/run/docker.sock]--> [Privilege Escalation]
[Terminales SIGMA] --[TCP 11010]--> [Servidor MorphoManager]
[Servidor MorphoManager] --[TCP 42100]--> [API de Gestión]
[Servidor MorphoManager] --[LDAP/AD Port]--> [Active Directory DC]
[Dispositivos Morpho] --[UDP 32001/32002]--> [Broadcast: Network Mapping]


[DNS RESOLUCIÓN INTERNA]
========================

[cbs.hcg.gob.mx] --> [10.2.1.141]
[api-sigma.hcg.gob.mx] --> [10.2.1.139]
[expediente.hcg.gob.mx] --> [10.2.1.140]
[empleado.hcg.gob.mx] --> [10.2.1.140]
[pah.hcg.gob.mx] --> [10.2.1.140]
[intranet.hcg.gob.mx] --> [10.2.1.140]
[sah.hcg.gob.mx] --> [10.2.1.141]
[pp.hcg.gob.mx] --> [10.2.1.141]
[certificados.hcg.gob.mx] --> [10.2.1.165]
[sii.hcg.gob.mx] --> [10.2.1.136]
[portal.hcg.gob.mx] --> [10.2.1.12]
[correo.opdhcg.net] --> [10.2.1.46]
[opd-hcg.org] --> [10.2.1.1, 10.2.1.18]
[HCGINFMED] --> [10.2.1.7]
[SYNHCGV] --> [10.1.61.16]
[SYNHCGN] --> [10.2.61.17]
[jim3] --> [10.2.1.11]
[pesopd.opd-hcg.org] --> [10.2.22.76]
```
```

### 2.8 PUNTOS DE PIVOTE IDENTIFICADOS

| Host | IP | Función | Utilidad para Pivoting |
|------|-----|---------|----------------------|
| www.hcg.gob.mx | 201.131.132.131 | Web Server | Punto de entrada inicial, posible dual-homed |
| 10.254.117.118 | 10.254.117.118 | Client WiFi | Beachhead interno, privilegios administrativos |
| 10.254.0.1 | 10.254.0.1 | Gateway | Control de tráfico entre segmentos |
| 10.2.1.1 | 10.2.1.1 | DC/LDAP | Control total de dominio si comprometido |
| 10.2.1.140 | 10.2.1.140 | Expedientes | Acceso a PHI, puente hacia Sigma |
| 10.2.1.92 | 10.2.1.92 | SMB Server | Recursos compartidos, lateral movement |

### 2.9 Transportes Winsock

| Transporte | Descripción |
|------------|-------------|
| Tcpip6 | TCP/IP IPv6 |
| Tcpip | TCP/IP IPv4 |
| vmbus | Hyper-V Virtual Bus |
| Psched | Packet Scheduler |
| afunix | AF_UNIX Sockets |
| RFCOMM | Bluetooth RFCOMM |

### 2.10 Entradas Winsock Catalog

| ID | Descripción | Familia | Socket | Protocolo |
|----|-------------|---------|--------|-----------|
| 1001 | MSAFD Tcpip [TCP/IPv6] | 23 (IPv6) | Stream | 6 (TCP) |
| 1002 | MSAFD Tcpip [UDP/IPv6] | 23 (IPv6) | Dgram | 17 (UDP) |
| 1003 | MSAFD Tcpip [RAW/IPv6] | 23 (IPv6) | Raw | 0 |
| 1004 | MSAFD Tcpip [TCP/IP] | 2 (IPv4) | Stream | 6 (TCP) |
| 1005 | MSAFD Tcpip [UDP/IP] | 2 (IPv4) | Dgram | 17 (UDP) |
| 1006 | MSAFD Tcpip [RAW/IP] | 2 (IPv4) | Raw | 0 |
| 1007 | Hyper-V RAW | 34 | Stream | 1 |
| 1008 | Proveedor servicios RSVP TCPv6 | 23 | Stream | 6 |
| 1009 | Proveedor servicios RSVP TCP | 2 | Stream | 6 |
| 1010 | Proveedor servicios RSVP UDPv6 | 23 | Dgram | 17 |
| 1011 | Proveedor servicios RSVP UDP | 2 | Dgram | 17 |
| 1012 | AF_UNIX | 1 | Stream | 0 |
| 1013 | MSAFD L2CAP [Bluetooth] | 32 | Stream | 256 |
| 1014 | MSAFD RfComm [Bluetooth] | 32 | Stream | 3 |
---

## [SECCIÓN 3: CONFIGURACIÓN DE SERVIDORES Y NODOS]

### 3.1 ACTIVOS DE INFRAESTRUCTURA EXTERNA

#### ACTIVO-WEB-01 (Portal Institucional HCG)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | ACTIVO-WEB-01 |
| **IP Principal** | 201.131.132.131 |
| **FQDN** | hcg.gob.mx, www.hcg.gob.mx |
| **Fabricante** | Microsoft (Windows Server) / Apache Foundation |
| **Sistema Operativo** | Windows Server (Arquitectura Win64) |
| **Servidor Web** | Apache HTTP Server v2.4.38, Microsoft IIS v10.0 |
| **Lenguajes** | PHP v7.1.26 (EOL), ASP.NET Core |
| **CMS** | Drupal v7 |
| **Certificado SSL** | *.hcg.gob.mx (Expira: May 2026) |
| **Librerías** | OpenSSL v1.0.2q (EOL Dic 2019), php-svg-lib, oniguruma |
| **Puertos Expuestos** | 80/TCP, 443/TCP |
| **Rol** | Servidor web principal y portal institucional |

#### ACTIVO-ICS-01 (Controlador Industrial HVAC)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | ACTIVO-ICS-01 (OBJETIVO-ALPHA) |
| **IP Externa** | 66.24.102.44 |
| **IP Interna** | 192.168.1.30 |
| **Fabricante** | Delta Controls |
| **Modelo** | enteliBUS Manager Touch eBMGR-TCH |
| **Versión Software** | V3.40 |
| **Protocolo** | BACnet/IP |
| **Puerto** | 47808/UDP |
| **Librería** | main.so (Servicio dactetra BACnet) |
| **Rol** | Controlador industrial de HVAC (Climatización) y gestión de edificios |
| **CVE Crítico** | CVE-2019-9569 (CVSS 9.8) |

#### ACTIVO-SURV-01 (Nodo de Videovigilancia)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | ACTIVO-SURV-01 (OBJETIVO-BETA) |
| **IP** | 211.21.101.106 |
| **Sistema Operativo** | Linux Embebido |
| **Servidor Web** | Nginx v1.14.x |
| **Puerto RTSP** | 554/TCP |
| **Puerto NetBIOS** | 137/UDP (WORKGROUP\WEBCAM) |
| **Módulo** | ngx_http_mp4_module |
| **Rol** | Nodo de videovigilancia (Cámara IP / NVR) |

### 3.2 ACTIVOS DE INFRAESTRUCTURA INTERNA

#### SERVIDOR-DC-01 (Controlador de Dominio)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-DC-01 |
| **IP Principal** | 10.2.1.1 |
| **IP Secundaria** | 10.2.1.18 |
| **FQDN** | opd-hcg.org |
| **Rol** | Controlador de Dominio / DNS / LDAP |
| **Puertos** | 389/TCP (LDAP), 53/UDP (DNS) |

#### SERVIDOR-SIGMA-01 (Sistema SIGMA)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-SIGMA-01 |
| **IP** | 10.2.1.139 |
| **FQDN** | sigma.hcg.gob.mx, api-sigma.hcg.gob.mx |
| **Rol** | Sistema SIGMA HCG / API REST / Infraestructura Biométrica |
| **Puertos** | 80/TCP, 443/TCP |
| **Sensibilidad** | ALTA - PHI/PII/Biometric Templates |

#### SERVIDOR-MULTIAPP-01 (Servidor Multiaplicación)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-MULTIAPP-01 |
| **IP** | 10.2.1.140 |
| **FQDN** | expediente.hcg.gob.mx, empleado.hcg.gob.mx, pah.hcg.gob.mx, intranet.hcg.gob.mx |
| **Rol** | Expediente electrónico, Portal empleado, PAH, Intranet |
| **Puertos** | 80/TCP, 443/TCP, 3389/TCP (RDP), 445/TCP (SMB) |

#### SERVIDOR-CBS-01 (Servicios Hospitalarios)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-CBS-01 |
| **IP** | 10.2.1.141 |
| **FQDN** | cbs.hcg.gob.mx, sah.hcg.gob.mx, pp.hcg.gob.mx |
| **Rol** | Servidor CBS, SAH y PP HCG |
| **Puertos** | 80/TCP, 443/TCP |

#### SERVIDOR-CERT-01 (Certificados Digitales)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-CERT-01 |
| **IP** | 10.2.1.165 |
| **FQDN** | certificados.hcg.gob.mx |
| **Rol** | Servidor de Certificados Digitales HCG |

#### SERVIDOR-CORREO-01 (Servidor de Correo)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-CORREO-01 |
| **IP** | 10.2.1.46 |
| **FQDN** | correo.opdhcg.net |
| **Rol** | Servidor de correo |

#### SERVIDOR-SII-01 (Sistema Información Institucional)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-SII-01 |
| **IP** | 10.2.1.136 |
| **FQDN** | sii.hcg.gob.mx |
| **Rol** | Sistema de Información Institucional |

#### SERVIDOR-PORTAL-01 (Portal Interno)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-PORTAL-01 |
| **IP** | 10.2.1.12 |
| **FQDN** | portal.hcg.gob.mx |
| **Rol** | Portal interno |

#### SERVIDOR-JIM3

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-JIM3 |
| **IP** | 10.2.1.11 |
| **Hostname** | jim3 |
| **Rol** | [DATO_PENDIENTE_DE_CONFIRMACIÓN] |

#### SERVIDOR-HCGINFMED (Información Médica)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-HCGINFMED |
| **IP** | 10.2.1.7 |
| **Hostname** | HCGINFMED |
| **Rol** | Servidor de Información Médica |

#### SERVIDOR-SYNHCGV (Sincronización Virtual)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-SYNHCGV |
| **IP** | 10.1.61.16 |
| **Hostname** | SYNHCGV |
| **Rol** | Servidor de Sincronización Virtual |

#### SERVIDOR-SYNHCGN (Sincronización Nodo)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-SYNHCGN |
| **IP** | 10.2.61.17 |
| **Hostname** | SYNHCGN |
| **Puertos** | 3306/TCP (MySQL) |
| **Rol** | Servidor de Sincronización Nodo / MySQL |

#### SERVIDOR-PESOPD

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | SERVIDOR-PESOPD |
| **IP** | 10.2.22.76 |
| **FQDN** | pesopd.opd-hcg.org |
| **Rol** | [DATO_PENDIENTE_DE_CONFIRMACIÓN] |

#### SERVIDOR-SMB-01 (10.2.1.92)

| Parámetro | Valor |
|-----------|-------|
| **IP** | 10.2.1.92 |
| **Rol** | Servidor de archivos SMB |
| **Shares Accesibles** | FAA_divserv_admvos, ADMIN$, C$, AlmacenFAA, Coordinacion Juridico, FAAJIMHCO-Viveres, JIM_DivServ_Admvos, vinculacionhistorico2019-2022 |
| **Usuario SMB Activo** | 10524DIVSERADMI\jlang (user 2020205) |
| **Credencial Dominio Almacenada** | Sí (usuario 2020205) |
| **WinRM Accesible** | No (error: WinRM no disponible / equipo no unido a dominio) |

### 3.3 Cluster Tomcat Interno (ACTIVO-INTERNAL-TOMCAT)

| Nodo | IP | Rol | Vulnerabilidad |
|------|-----|-----|----------------|
| Nodo 1 | 10.254.185.35 | Servidor de aplicaciones | Ghostcat (CVE-2020-1938) |
| Nodo 2 | 10.254.3.193 | Servidor de aplicaciones | Ghostcat (CVE-2020-1938) |
| Nodo 3 | 10.254.225.221 | Servidor de aplicaciones | Ghostcat (CVE-2020-1938) |
| Nodo 4 | 10.254.30.158 | Servidor de aplicaciones | Ghostcat (CVE-2020-1938) |

### 3.4 Sistema Biométrico (MorphoManager / SIGMA)

#### Terminal Biométrica (ACTIVO-ID-02)

| Parámetro | Valor |
|-----------|-------|
| **ID Activo** | ACTIVO-ID-02 |
| **IP** | 10.254.12.37 |
| **Hostname** | Device-A |
| **Modelo** | SIGMA Extreme |
| **Rol** | Terminal biométrica |

#### Servidor MorphoManager

| Parámetro | Valor |
|-----------|-------|
| **Nombre** | MorphoManager Server |
| **Rol** | Gestión de terminales SIGMA |
| **Subredes de Gestión** | 10.254.0.0/16, 10.2.0.0/16 |

#### Puertos de Servicio MorphoManager

| Puerto | Protocolo | Servicio | Vulnerabilidad |
|--------|-----------|----------|----------------|
| TCP 11010 | Thrift RPC | Comunicación terminales | CVE-2019-0205 (Deserialización) |
| TCP 42100 | SOAP API | API de gestión | XXE, Inyección SOAP, Buffer Overflow |
| TCP 11001 | Updates | Actualización firmware | RCE sin validación de firma |
| UDP 32001 | Broadcast | Discovery dispositivos | Fuga de información (CWE-200) |
| UDP 32002 | Broadcast | Discovery dispositivos | Fuga de información (CWE-200) |

### 3.5 ADAPTADORES DE RED (Host Origen)

#### Adaptador Principal: Intel(R) Ethernet Connection (7) I219-V

| Parámetro | Valor |
|-----------|-------|
| **Tipo** | Ethernet física |
| **Device ID** | `PCI\VEN_8086&DEV_15BC&SUBSYS_312A17AA&REV_10\3&11583659&0&FE` |
| **Instance GUID** | `{23ECA94A-84CD-4140-A44C-6D96573B69D5}` |
| **Nombre de Conexión** | `Ethernet` |
| **Interface Index** | 3 |
| **IP IPv4** | 10.1.7.238 |
| **Máscara** | 255.255.255.0 |
| **Gateway** | 10.1.7.254, fe80::a68c:dbff:fee6:4701%3 |
| **DNS** | 148.202.3.5, 8.8.8.8 |
| **MAC** | 2C:F0:5D:1C:B0:AD |
| **Driver** | `e1d68x64.sys` v12.19.0001.0037 |
| **Driver Date** | 11/10/2021 12:45:24 |
| **DHCP** | No |
| **Velocidad** | 1 Gbps |
| **FIPS 140** | Sí |
| **802.11w MFP** | Habilitado |
| **Hosted Network** | No soportado |
| **IHV DLL** | C:\WINDOWS\system32\IntelIHVRouter06.dll |
| **IAID DHCPv6** | 204271709 |
| **DUID DHCPv6** | 00-01-00-01-27-99-0C-D9-2C-F0-5D-1C-B0-AD |

#### Adaptador Wi-Fi: Intel(R) Dual Band Wireless-AC 8265

| Parámetro | Valor |
|-----------|-------|
| **Device ID** | `PCI\VEN_8086&DEV_24FD&SUBSYS_10108086&REV_78\E884A5FFFFEB781E00` |
| **GUID** | `{526B708E-0844-4ED3-A305-2E8912AA667B}` |
| **MAC** | E8:84:A5:EB:78:1E |
| **Driver** | `Netwtw06.sys` v20.70.0030.0001 / v22.160.0.4 |
| **Driver Date** | 9/22/2022 14:28:32 / 14/08/2022 |
| **Radio Types** | 802.11b/g/n/a/ac |
| **Bandas** | 2.4 GHz, 5 GHz |
| **Estado** | Desconectado |

#### Adaptador Bluetooth PAN

| Parámetro | Valor |
|-----------|-------|
| **Device ID** | `bth#ms_bthpan#6&399f715f&0&2` |
| **MAC** | E8:84:A5:EB:78:22 |
| **Estado** | Desconectado |

#### Adaptadores Virtuales

| Interfaz | IP | MAC | Tipo |
|----------|-----|-----|------|
| vEthernet (Default Switch) | 172.27.16.1 / 172.21.240.1 | 00:15:5D:C7:F9:03 | Hyper-V |
| vEthernet (WSL Hyper-V firewall) | 172.22.224.1 | N/A | WSL |
| Docker | 10.254.178.36 | 8A:66:36:F4:79:92 | Docker |
| Hotspot | 192.168.137.1 | EA:84:A5:EB:78:1E | Virtual |

#### NDIS Offload Configuration (Intel I219-V)

| Parámetro | Valor |
|-----------|-------|
| Header.Type | 167 |
| Header.Revision | 7 |
| Header.Size | 216 |
| LsoV2.IPv4.MaxOffLoadSize | 64240 |
| LsoV2.IPv4.MinSegmentCount | 2 |
| LsoV2.IPv6.MaxOffLoadSize | 64240 |
| LsoV2.IPv6.MinSegmentCount | 2 |
| NumberOfReceiveQueues | 2 |
| MacOptions | 0x2CD |

### 3.6 Gateways Detectados

| IP Gateway | MAC | Segmento | Tipo |
|------------|-----|----------|------|
| 10.1.7.254 | ec-7c-2c-c0-f7-03 | Principal IT | Físico |
| 192.168.137.1 | EA:84:A5:EB:78:1E | Hotspot | Virtual |
| 10.254.0.1 | N/A | WiFi/VLAN Gestión | N/A |

### 3.7 Servidores DNS

| Servidor | IP | Tipo |
|----------|-----|------|
| Primario Externo | 148.202.3.5 | Externo |
| Secundario Externo | 8.8.8.8 | Externo (Google) |
| Interno DC | 10.2.1.1 | DC/DNS Local |

### 3.8 Network Bindings (Intel I219-V)

| Componente | Estado |
|------------|--------|
| ms_tcpip (IPv4) | Habilitado |
| ms_tcpip6 (IPv6) | Habilitado |
| ms_rdma_ndk (RDMA NDK) | Habilitado |
| ms_ndiscap (NDIS Capture) | Habilitado |
| ms_lldp (LLDP Protocol) | Habilitado |
| ms_pacer (QoS Packet Scheduler) | Habilitado |
| ms_pppoe (PPPoE) | Habilitado |
| ms_rspndr (Link-Layer Topology Discovery Responder) | Habilitado |
| ms_lltdio (Link-Layer Topology Discovery Mapper I/O Driver) | Habilitado |
| ms_msclient (Client for Microsoft Networks) | Habilitado |
| ms_server (File and Printer Sharing) | Habilitado |
| ms_netbios (NetBIOS Interface) | Habilitado |
| ms_netbt (WINS Client) | Habilitado |
| INSECURE_NPCAP (Npcap Packet Driver) | Habilitado |
| vms_pp (Hyper-V Extensible Switch) | **DESHABILITADO** |
| ms_implat (Network Adapter Multiplexor Protocol) | **DESHABILITADO** |

### 3.9 VIRTUAL SWITCH (HYPER-V)

#### VmSwitch Version

| Parámetro | Valor |
|-----------|-------|
| **Versión Máxima Soportada** | 19.0 |
| **Versión Detectada** | 19.0 |

#### VmSwitch Features (Capabilities)

| ID | Feature | Estado |
|----|---------|--------|
| 1 | VmsCapabilityFeatureExtensibilityStackBypass | Found |
| 2 | VmsCapabilityFeatureUntrustedGuestIsolation | Found |
| 3 | VmsCapabilityFeaturePacketTracking | Found |
| 4 | VmsCapabilityFeatureNblOobIndicateUncachedData | Found |
| 5 | VmsCapabilityFeatureSuspendedLiveMigration | Found |
| 6 | VmsCapabilityFeatureIndependentHostSpreading | Found |
| 8 | VmsCapabilityFeatureVersionedIoctl | Found |
| 9 | VmsCapabilityFeatureQueryVlanInfo | Found |
| 10 | VmsCapabilityFeatureSoftwareRscOnPhysicalNic | Found |
| 11 | VmsCapabilityFeatureLightweightMiniports | Found |
| 12 | VmsCapabilityFeatureDisableVmNicIM | Found |
| 13 | VmsCapabilityFeatureNrtNameResolutionId | Found |
| 14 | VmsCapabilityFeatureVmbusAffinityPolicy | Found |
| 15 | VmsCapabilityFeatureHostVNicProxy | Found |
| 16 | VmsCapabilityFeatureReloadability | Found |
| 17 | VmsCapabilityFeaturePacketMonitor | Found |
| 18 | VmsCapabilityFeatureDynamicVMMQ | Found |
| 19 | VmsCapabilityFeatureStateSeparation | Found |
| 20 | VmsCapabilityFeatureHardwarePacketTimestamp | Found |
| 21 | VmsCapabilityFeatureQueryCapabilitiesIoctl | Found |
| 22 | VmsCapabilityFeatureVmPhuZeroReloadability | Found |
| 23 | VmsCapabilityFeatureConfigureSwitchPerfParameters | Found |
| 24 | VmsCapabilityFeatureHostNicUseL2IndirectionTable | Found |
| 25 | VmsCapabilityFeatureConfigureGlobalsUsingIoctl | Found |
| 26 | VmsCapabilityFeatureReloadSensitiveIoctls | Found |
| 27 | VmsCapabilityFeatureNonConsecutiveRssCpus | Found |
| 28 | VmsCapabilityFeatureRscOnVPortLevel | Found |
| 29 | VmsCapabilityFeatureConfigureSwitchExtensionParameters | Found |

### 3.10 Puertos en Escucha (TCP) - Host Origen

| Puerto | Servicio | PID |
|--------|----------|-----|
| 22 | SSH (OpenSSH Server) | 5580 |
| 80 | HTTP | 4 |
| 135 | RPC | 1464 |
| 139 | NetBIOS | 4 |
| 443 | HTTPS | 4 |
| 445 | SMB | 4 |
| 2179 | Hyper-V | 3700 |
| 3389 | RDP | 1748 |
| 5357 | WSDAPI | 4 |
| 5432 | PostgreSQL | 7536 |
| 7680 | MS Delivery Optimization | 15312 |
| 8080 | HTTP Alt | 5532 |
| 42050 | N/D | 6376 |
| 49664-49672 | RPC Dinámico | Varios |
| 50080 | N/D | 4 |
| 50443 | N/D | 4 |

#### Conexiones TCP Establecidas (Internas)

| Remote Address | Remote Port | PID | Servicio |
|----------------|-------------|-----|----------|
| 10.2.1.92 | 445 | 4 | SMB |
| 10.1.85.25 | 7680 | 15312 | MS Delivery Optimization |

### 3.11 DISPOSITIVOS DE SISTEMA (PCI)

| Dispositivo | Device ID | Driver | Versión |
|-------------|-----------|--------|---------|
| NVM Express Controller | `PCI\VEN_15B7&DEV_5006` | stornvme.sys | 10.00.26100.7920 |
| Intel USB 3.1 eXtensible Host | `PCI\VEN_8086&DEV_A36D` | USBXHCI.SYS | 10.00.26100.7920 |
| Intel 300 Series LPC (B360) | `PCI\VEN_8086&DEV_A308` | msisadrv.sys | 10.00.26100.1150 |
| Intel Gaussian Mixture Model | `PCI\VEN_8086&DEV_1911` | n/a | - |
| Intel Dual Band Wireless-AC 8265 | `PCI\VEN_8086&DEV_24FD` | Netwtw06.sys | 20.70.0030.0001 |
| Intel SMBus | `PCI\VEN_8086&DEV_A323` | n/a | - |
| High Definition Audio Controller | `PCI\VEN_8086&DEV_A348` | hdaudbus.sys | 10.00.26100.7920 |
| Intel Ethernet I219-V | `PCI\VEN_8086&DEV_15BC` | e1d68x64.sys | 12.19.0001.0037 |
| Intel Management Engine | `PCI\VEN_8086&DEV_A360` | TeeDriverW10x64.sys | 2145.01.0042.0000 |
| Intel PCI Express Root Port #6 | `PCI\VEN_8086&DEV_A33D` | pci.sys | 10.00.26100.7920 |
| Intel Host Bridge/DRAM | `PCI\VEN_8086&DEV_3E30` | n/a | - |
| Intel PCI Express Root Port #21 | `PCI\VEN_8086&DEV_A32C` | pci.sys | 10.00.26100.7920 |
| Intel SPI Controller | `PCI\VEN_8086&DEV_A324` | n/a | - |
| Intel SATA AHCI Controller | `PCI\VEN_8086&DEV_A352` | iaStorAC.sys | 17.11.0000.1000 |
| Intel UHD Graphics 630 | `PCI\VEN_8086&DEV_3E98` | igdkmd64.sys | 31.00.0101.2115 |

### 3.12 ADAPTADORES WAN/VPN (Microsoft RAS)

| Adaptador | Device ID Pattern | Estado OID |
|-----------|-------------------|------------|
| ms_ndiswanipv6 | swd#msrras#ms_ndiswanipv6 | CreateFile error=31 |
| ms_pppoeminiport | swd#msrras#ms_pppoeminiport | CreateFile error=31 |
| ms_sstpminiport | swd#msrras#ms_sstpminiport | CreateFile error=31 |
| ms_ndiswanip | swd#msrras#ms_ndiswanip | CreateFile error=31 |
| ms_ndiswanbh | swd#msrras#ms_ndiswanbh | CreateFile error=31 |
| ms_agilevpnminiport | swd#msrras#ms_agilevpnminiport | OID errors (50) |
| ms_pptpminiport | swd#msrras#ms_pptpminiport | CreateFile error=31 |
| ms_l2tpminiport | swd#msrras#ms_l2tpminiport | CreateFile error=31 |

### 3.15 Adaptadores de Red - Vista Completa

| DeviceID | Descripción | MAC | Estado | Velocidad | Tipo |
|----------|-------------|-----|--------|-----------|------|
| 0 | Intel Ethernet (7) I219-V | 2C:F0:5D:1C:B0:AD | Conectado | 1 Gbps | Físico |
| 1 | Microsoft Kernel Debug Network Adapter | N/A | Virtual | N/A | Virtual |
| 2 | Intel Dual Band Wireless-AC 8265 | E8:84:A5:EB:78:1E | Desconectado | N/A | Físico |
| 3 | Microsoft Wi-Fi Direct Virtual Adapter | E8:84:A5:EB:78:1F | Virtual | N/A | Virtual |
| 4 | WAN Miniport (SSTP) | N/A | Virtual | N/A | Virtual |
| 5 | WAN Miniport (IKEv2) | N/A | Virtual | N/A | Virtual |
| 6 | WAN Miniport (L2TP) | N/A | Virtual | N/A | Virtual |
| 7 | WAN Miniport (PPTP) | N/A | Virtual | N/A | Virtual |
| 8 | WAN Miniport (PPPOE) | N/A | Virtual | N/A | Virtual |
| 9 | WAN Miniport (IP) | E6:FB:20:52:41:53 | Virtual | N/A | Virtual |
| 10 | WAN Miniport (IPv6) | EA:93:20:52:41:53 | Virtual | N/A | Virtual |
| 11 | WAN Miniport (Network Monitor) | EC:6A:20:52:41:53 | Virtual | N/A | Virtual |
| 12 | Microsoft Wi-Fi Direct Virtual Adapter #2 | EA:84:A5:EB:78:1E | Conectado | N/A | Virtual |
| 13 | Hyper-V Virtual Switch Extension | N/A | Virtual | N/A | Virtual |
| 14 | RAS Async Adapter | N/A | Virtual | N/A | Virtual |
| 15 | Bluetooth Device (PAN) | E8:84:A5:EB:78:22 | Desconectado | 3 Mbps | Físico |

---

## [SECCIÓN 4: LOGS Y EVENTOS TÉCNICOS]

### 4.1 Eventos de Error Críticos

| Evento | Descripción | Fecha/Período | Componente |
|--------|-------------|---------------|------------|
| BEX64 / AppCrash | Fallo recurrente en wia.dll | Enero-Marzo 2026 | svchost.exe_StiSvc |
| CLR20r3 | Fallo en System.Private.CoreLib | N/D | GestionDocumental.Presentation.exe |
| WinSetupDiag02 | Error 0x800704C7 en actualización | N/D | Windows Update |

### 4.2 Parches Instalados

| KB | Fecha Instalación | Tipo |
|----|-------------------|------|
| KB5077241 | 2026-02-26 | Update |
| KB5077371 | 2026-02-26 | Update |
| KB5074828 | 2026-01-30 | Update |
| KB5054156 | 2026-01-06 | Update |

### 4.3 Estado de Firewall

| Perfil | Estado | Política | RemoteManagement |
|--------|--------|----------|------------------|
| Dominio | ACTIVAR | BlockInbound, AllowOutbound | Deshabilitado |
| Privado | ACTIVAR | BlockInbound, AllowOutbound | Deshabilitado |
| Público | ACTIVAR | BlockInbound, AllowOutbound | Deshabilitado |

### 4.4 Configuración Global IPsec

| Parámetro | Valor |
|-----------|-------|
| StrongCRLCheck | 0 (Deshabilitado) |
| SAIdleTimeMin | 5min |
| DefaultExemptions | DetecciónVecinos, DHCP |
| IPsecThroughNAT | Nunca |
| StatefulFTP | Habilitar |
| StatefulPPTP | Habilitar |

### 4.5 Reglas de Firewall Activas (Resumen)

| Nombre de Regla | Perfiles | Protocolo | Puerto | Acción |
|-----------------|----------|-----------|--------|--------|
| Conexión compartida a Internet | Dominio, Privada, Pública | Cualquiera | Cualquiera | Permitir |
| HNS Container Networking - DNS | Dominio, Privada, Pública | UDP/TCP | 53 | Permitir |
| Google Chrome (mDNS) | Dominio, Privada, Pública | UDP | 5353 | Permitir |
| Microsoft Edge (mDNS-In) | Dominio, Privada, Pública | UDP | 5353 | Permitir |
| Microsoft Teams | Dominio, Privada, Pública | Cualquiera | Cualquiera | Permitir |
| AnyDesk | Privada, Pública | TCP/UDP | Cualquiera | Permitir |
| Escritorio remoto (TCP/UDP) | Dominio, Privada, Pública | TCP/UDP | 3389 | Permitir |
| Node.js JavaScript Runtime | Pública | TCP/UDP | Cualquiera | Permitir |

### 4.6 Reglas Network Discovery

| Regla | Estado |
|-------|--------|
| Network Discovery (LLMNR-UDP-Out) | NO CONFIGURADA |
| Network Discovery (NB-Datagram-Out) | NO CONFIGURADA |
| Network Discovery (NB-Name-Out) | NO CONFIGURADA |
| Network Discovery (Pub WSD-Out) | NO CONFIGURADA |
| Network Discovery (SSDP-Out) | NO CONFIGURADA |
| Network Discovery (UPnPHost-Out) | NO CONFIGURADA |
| Network Discovery (UPnP-Out) | NO CONFIGURADA |
| Network Discovery (WSD Events-Out) | NO CONFIGURADA |
| Network Discovery (WSD EventsSecure-Out) | NO CONFIGURADA |
| Network Discovery (WSD-Out) | NO CONFIGURADA |

### 4.7 WinRM Status

| Parámetro | Valor |
|-----------|-------|
| Estado | No iniciado |
| Trusted Hosts | No configurado (WSMan path no existe) |
| Kerberos Tickets Cached | 0 |
| Logon Session ID | 0x350a2 |

### 4.8 Artifacts en C:\temp

| Archivo | Tamaño (bytes) | Fecha Modificación |
|---------|----------------|-------------------|
| active_connections.txt | 24,066 | 2026-03-03 19:12 |
| autoruns.txt | 3,160 | 2026-03-03 19:50 |
| fw_inbound_allow.txt | 65,838 | 2026-03-03 19:50 |
| fw_ports.txt | 4,694 | 2026-03-03 19:50 |
| local_admins.txt | 590 | 2026-03-03 19:50 |
| local_users.txt | 1,718 | 2026-03-03 19:50 |
| neighbors.txt | 184,594 | 2026-03-03 19:12 |
| network_config.txt | 3,506 | 2026-03-03 19:09 |
| routing_table.txt | 14,534 | 2026-03-03 19:12 |
| system_patches.txt | 602 | 2026-03-03 19:50 |
| third_party_services.txt | 2,676 | 2026-03-03 19:50 |

### 4.9 Registry Checks

| Check | Resultado |
|-------|-----------|
| AlwaysInstallElevated_HKCU | No encontrado (no aplica) |
| AlwaysInstallElevated_HKLM | No encontrado (no aplica) |
| Unquoted Service Paths | FINDSTR: no hay cadenas (ninguna encontrada) |

### 4.10 Estadísticas de Interfaz

| Métrica | Valor |
|---------|-------|
| Bytes Recibidos | 3,194,791,370 |
| Bytes Enviados | 1,299,982,326 |
| Paquetes Unicast Recibidos | 7,535,394 |
| Paquetes Unicast Enviados | 11,221,700 |
| Paquetes No-Unicast Recibidos | 12,586,587 |
| Paquetes No-Unicast Enviados | 3,543,823 |
| Descartados Recibidos | 0 |
| Descartados Enviados | 0 |
| Errores Recibidos | 0 |
| Errores Enviados | 0 |

---

## [SECCIÓN 5: DEPENDENCIAS Y SERVICIOS]

### 5.1 Servicios de Red Activos

| Servicio | Tipo | Estado | PID | Modo Inicio | Cuenta |
|----------|------|--------|-----|-------------|--------|
| lanmanserver | WIN32 | RUNNING | 5656 | Auto | LocalSystem |
| nativewifip | KERNEL_DRIVER | RUNNING | 0 | Demand | N/A |
| wlansvc | WIN32_OWN_PROCESS | RUNNING | 4584 | Auto | LocalSystem |
| dhcp | WIN32_SHARE_PROCESS | RUNNING | 4292 | Auto | NT Authority\LocalService |
| fdrespub | WIN32 | RUNNING | 10760 | Auto | N/A |
| upnphost | WIN32 | RUNNING | 2024 | Auto | N/A |
| wcncsvc | WIN32_SHARE_PROCESS | STOPPED | 0 | N/A | N/A |
| eaphost | WIN32_OWN_PROCESS | STOPPED | 0 | N/A | N/A |

### 5.2 Servicios de Hyper-V

| Servicio | Nombre Descriptivo | Estado | Código |
|----------|-------------------|--------|--------|
| vmbus | Bus de máquina virtual | **STOPPED** | 1 |
| VMBusHID | VMBusHID | **STOPPED** | 1 |
| vmbusproxy | vmbusproxy | **STOPPED** | 1 |
| vmbusr | Proveedor del bus de máquina virtual | **RUNNING** | 4 |
| vmcompute | Servicio de proceso de host de Hyper-V | **RUNNING** | 4 |
| vmgid | Controlador de infraestructura de invitado de Microsoft Hyper-V | **STOPPED** | 1 |
| vmicguestinterface | Interfaz de servicio invitado de Hyper-V | **STOPPED** | 1 |
| vmicheartbeat | Servicio de latido de Hyper-V | **STOPPED** | 1 |
| vmickvpexchange | Servicio de intercambio de datos de Hyper-V | **STOPPED** | 1 |
| vmicrdv | Servicio de virtualización de Escritorio remoto de Hyper-V | **STOPPED** | 1 |
| vmicshutdown | Servicio de cierre de invitado de Hyper-V | **STOPPED** | 1 |
| vmictimesync | Servicio de sincronización de hora de Hyper-V | **STOPPED** | 1 |
| vmicvmsession | Servicio PowerShell Direct de Hyper-V | **STOPPED** | 1 |
| vmicvss | Solicitante de instantáneas de volumen de Hyper-V | **STOPPED** | 1 |
| vmms | Administración de máquinas virtuales de Hyper-V | **RUNNING** | 4 |
| vmsmp | vmsmp | **RUNNING** | 4 |
| VMSNPXY | VmSwitch NIC Proxy Driver | **RUNNING** | 4 |
| VMSP | VmSwitch Protocol Driver | **RUNNING** | 4 |
| VmsProxy | VmSwitch Proxy Driver | **RUNNING** | 4 |
| VMSVSF | VmSwitch Extensibility Filter | **STOPPED** | 1 |
| VMSVSP | VmSwitch Extensibility Protocol | **STOPPED** | 1 |

### 5.3 Dependencias de Servicios

| Servicio | Depende de |
|----------|------------|
| wlansvc | nativewifip, RpcSs, Ndisuio, wcmsvc |
| dhcp | NSI, Afd |

### 5.4 Servicios de Monitoreo/Actualización Detectados

| Servicio | DisplayName |
|----------|-------------|
| AarSvc_b98dd | Agent Activation Runtime_b98dd |
| AdobeARMservice | Adobe Acrobat Update Service |
| DevQueryBroker | Agente de detección en segundo plano de DevQuery |
| DmEnrollmentSvc | Device Management Enrollment Service |
| edgeupdate | Microsoft Edge Update Service (edgeupdate) |
| edgeupdatem | Microsoft Edge Update Service (edgeupdatem) |
| FrameServerMonitor | Monitor del servidor de marco de la Cámara de Windows |
| GoogleUpdaterInternalService147.0.7703.0 | Servicio interno de la herramienta de actualización de Google |
| GoogleUpdaterService147.0.7703.0 | Servicio de herramienta de actualización de Google |
| gupdate | Google Update Servicio (gupdate) |
| gupdatem | Google Update Servicio (gupdatem) |
| hpatchmon | Hotpatch Monitoring Service |
| McpManagementService | McpManagementService |
| NcbService | Agente de conexión de red |
| OneDrive Updater Service | OneDrive Updater Service |
| pgagent-pg18 | PostgreSQL Scheduling Agent - pgagent-pg18 |
| PolicyAgent | Agente de directiva IPsec |
| ssh-agent | OpenSSH Authentication Agent |
| SystemEventsBroker | Agente de eventos del sistema |
| TimeBrokerSvc | Agente de eventos de tiempo |
| WebManagement | Web Management |
| WinRM | Administración remota de Windows (WS-Management) |
| WMIRegistrationService | Intel(R) Management Engine WMI Provider Registration |
| wuauserv | Windows Update |
| XboxGipSvc | Xbox Accessory Management Service |

### 5.5 Servidor SMB (Host Origen)

| Parámetro | Valor |
|-----------|-------|
| Nombre Servidor | \\10524DIVSERADMI |
| Oculto | No |
| Máx Sesiones Abiertas | 20 |
| Máx Archivos por Sesión | 16384 |
| Tiempo Inactividad Sesión | 15 min |
| PID Servicio | 5656 |
| Interfaces Activas | NetbiosSmb, NetBT_Tcpip (4 interfaces) |

### 5.6 Recursos Compartidos (Host Origen)

| Nombre | Ruta | Descripción |
|--------|------|-------------|
| C$ | C:\ | Recurso predeterminado |
| IPC$ | N/A | IPC remota |
| print$ | C:\Windows\system32\spool\drivers | Controladores de impresora |
| ADMIN$ | C:\WINDOWS | Admin remota |
| DevelopmentFiles | C:\ProgramData\DeveloperTools | SMB Share For DevelopmentFiles |
| Scanner Ricoh | C:\Scanner Ricoh | Scanner |
| Users | C:\Users | Usuarios |
| HP Universal Printing PCL 6 (Copiar 1) | N/A | Impresora en cola |

### 5.7 Recursos SMB Expuestos (10.2.1.92)

| Recurso | Tipo |
|---------|------|
| ADMIN$ | Administrativo |
| C$ | Disco raíz |
| AlmacenFAA | Departamento |
| Coordinacion Juridico | Departamento |
| FAAJIMHCO-Viveres | Departamento |
| JIM_DivServ_Admvos | Departamento |
| vinculacionhistorico2019-2022 | Histórico |

### 5.8 Virtualización

#### Hyper-V

| Parámetro | Valor |
|-----------|-------|
| Enabled | true |
| Default Switch IP | 172.27.16.1 / 172.21.240.1 |
| WSL Firewall IP | 172.22.224.1 |
| VBS Check Script | hpatchmonTask.cmd (checks VirtualizationBasedSecurityStatus) |

#### Docker

| Parámetro | Valor |
|-----------|-------|
| Enabled | true |
| Desktop Path | C:\Program Files\Docker\Docker\Docker Desktop.exe |
| Hub User | j3susangar1ca |
| host.docker.internal | 10.254.178.36 |
| gateway.docker.internal | 10.254.178.36 |
| kubernetes.docker.internal | 127.0.0.1 |

#### WSL

| Parámetro | Valor |
|-----------|-------|
| Enabled | true |
| Network Adapter | vEthernet (WSL (Hyper-V firewall)) |
| IP | 172.22.224.1 |
| WSL Instance ARP IP | 172.22.226.149 |
| WSL Instance ARP MAC | 00-15-5D-CE-7A-63 |
| WSL Instance ARP State | Stale |

### 5.9 Impresoras

| Nombre | Puerto | Tipo |
|--------|--------|------|
| SHARP AR-M257 PCL6_T1 | 10.1.7.182 | Network IP |
| RICOH MP 4055 PCL 6 | IP_10.1.7.182 | Network IP |
| HP Universal Printing PCL 6 (Copiar 1) | 10.1.7.205 | Network IP |
| HP Universal Printing PCL 6 | 10.1.7.206 | Network IP |
| 5249 | 10.1.7.206_3 | Network IP |
| NPI2129B0 (HP LaserJet 400 M401dne) | WSD-20a27693... | WSD |
| HP LaserJet Pro M404-M405 [7E971F] | WSD-6cf27753... | WSD |
| HP LaserJet Pro M404-M405 UPD PCL 6 | WSD-a1749f69... | WSD |
| HP LaserJet P3010 Series UPD PCL 6 (Copy 1) | WSD-83e1c780... | WSD |
| HP LaserJet M402dn UPD PCL 6 (Copy 3) | WSD-31ece1e3... | WSD |
| HP LaserJet M402dn UPD PCL 6 (Copy 2) | WSD-549f3c17... | WSD |
| HP LaserJet M402dn UPD PCL 6 (Copy 1) | WSD-59bfd50d... | WSD |
| HP LaserJet M402dn UPD PCL 6 | WSD-ab34a479... | WSD |
| HP LaserJet 400 M401dn UPD PCL 6 | WSD-049e709d... | WSD |
| OneNote (Desktop) | nul: | Virtual |
| OneNote for Windows 10 | Microsoft.Office... | Virtual |
| Microsoft XPS Document Writer | PORTPROMPT: | Virtual |
| Microsoft Print to PDF | PORTPROMPT: | Virtual |
| Adobe PDF | Documents\*.pdf | Virtual |
| Fax | SHRFAX: | Virtual |

### 5.10 Tareas Programadas (No-Microsoft)

| Tarea | Path |
|-------|------|
| Git for Windows Updater | \ |
| HPCustParticipation HP LaserJet Pro M404-M405 | \ |
| MicrosoftEdgeUpdateTaskMachineCore | \ |
| MicrosoftEdgeUpdateTaskMachineUA | \ |
| npcapwatchdog | \ |
| OneDrive Per-Machine Standalone Update Task | \ |
| OneDrive Reporting Task-S-1-5-21-...-1001/1002/1003/1004/1005/1007 | \ |
| OneDrive Startup Task-S-1-5-21-...-1001/1002/1003/1004/1005/1007 | \ |
| User_Feed_Synchronization-{5A960A73...} | \ |
| S-1-5-21-...-1001 | \Agent Activation Runtime\ |
| GoogleUpdaterTaskSystem147.0.7703.0{...} | \GoogleSystem\GoogleUpdater\ |
| RunPlatformExperienceHelperOnUnlock | \GoogleUserPEH\ |
| Lenovo iM Controller Monitor | \Lenovo\ImController\ |
| Lenovo iM Controller Scheduled Maintenance | \Lenovo\ImController\ |
| LenovoSystemUpdatePlugin_WeeklyTask | \Lenovo\ImController\Plugins\ |
| 27945d47-4a1c-4152-af24-eb4bc9e78f53 | \Lenovo\ImController\TimeBased\ |
| 408ae645-3ffc-40a7-aeac-cbde51fd4910 | \Lenovo\ImController\TimeBased\ |
| e32bf678-ff8b-4e47-8e1c-605b5e8647fb | \Lenovo\ImController\TimeBased\ |
| f8762b8e-970e-4302-945b-f918c070be60 | \Lenovo\ImController\TimeBased\ |
| Lenovo.Vantage.ServiceMaintainance | \Lenovo\Vantage\ |
| SoftLandingCreativeManagementTask | \SoftLanding\ |
| SoftLandingDeferralTask-{...} | \SoftLanding\ |
| SoftLandingTriggerTask-128000000001615609-render-{...} | \SoftLanding\ |

### 5.11 Autoruns Startup

| Nombre | Comando |
|--------|---------|
| OneDriveSetup | C:\Windows\System32\OneDriveSetup.exe /thfirstsetup |
| netlogon6 | netlogon6.bat |
| OneDrive | "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background |
| Docker Desktop | C:\Program Files\Docker\Docker\Docker Desktop.exe |
| SecurityHealth | %windir%\system32\SecurityHealthSystray.exe |
| Lenovo Fundamental USB Keyboard | C:\Program Files (x86)\Lenovo\Lenovo Calliope USB Keyboard\SklFundKb.exe |
| RtkAudUService | C:\WINDOWS\System32\DriverStore\FileRepository\realtekservice.inf... |
| Enviar a OneNote | Enviar a OneNote.lnk |

### 5.12 Aplicaciones Instaladas con Firewall

- Google Chrome
- Chrome Remote Desktop Host (v146.0.7680.5)
- Microsoft OneDrive
- Docker Desktop
- AnyDesk
- Anytype
- Apache HTTP Server
- OpenSSH Server (sshd)
- Python
- Node.js
- Microsoft Teams
- Microsoft Teams (personal)
- Zoom Video Meetings
- Microsoft Lync
- Skype
- Microsoft Office (OneNote, Outlook, Groove)
- Microsoft Edge
- Hyper-V
- WSL2
- pgAdmin4
- PostgreSQL
- Git for Windows
- Npcap
- Lenovo Vantage
- Lenovo iM Controller
- HP Smart
- HP LaserJet software
- SoftLanding

### 5.13 Servicios Multicast/Broadcast

| IP Multicast | Servicio | Protocolo |
|--------------|----------|-----------|
| 224.0.0.22 | IGMP | Multicast Group |
| 224.0.0.251 | mDNS | DNS Multicast |
| 224.0.0.252 | LLMNR | Link-Local Multicast Name Resolution |
| 239.255.255.250 | SSDP | UPnP Device Discovery |

### 5.14 Nombres NetBIOS Locales

| Nombre | Tipo | Estado | Interfaz |
|--------|------|--------|----------|
| 10524DIVSERADMI<20> | Único | Registrado | Todas |
| 10524DIVSERADMI<00> | Único | Registrado | Todas |
| DIVSERADMIN<00> | Grupo | Registrado | Todas |
| DIVSERADMIN<1E> | Grupo | Registrado | Todas |
| DIVSERADMIN<1D> | Único | Conflicto | vEthernet |
| __MSBROWSE__<01> | Grupo | Registrado | vEthernet |

---

## [SECCIÓN 6: CREDENCIALES/SEGURIDAD]

### 6.1 USUARIOS LOCALES

| Username | Enabled | Password Required | Last Logon | Principal Source |
|----------|---------|-------------------|------------|------------------|
| Administrador | false | true | 2021-01-19T17:07:19 | Local |
| DefaultAccount | false | false | null | null |
| DevToolsUser | true | true | 2026-01-09T10:18:32 | null |
| Invitado | true | false | 2025-11-28T12:02:20 | null |
| jlang | true | true | null | MicrosoftAccount |
| postgres | true | true | 2026-03-02T08:18:35 | null |
| Soporte | true | false | 2026-03-03T19:07:01 | Local |
| Usuario | true | false | 2026-01-09T10:56:12 | Local |
| WDAGUtilityAccount | false | true | null | null |
| WsiAccount | false | false | 2026-01-09T10:01:30 | null |

### 6.2 USUARIO IDENTIFICADO (Activo)

| Parámetro | Valor |
|-----------|-------|
| **Username** | jlang |
| **UPN** | jlangarica@hcg.gob.mx |
| **Email** | jlangarica@hcg.gob.mx |
| **Dominio** | hcg.gob.mx |
| **SID** | S-1-5-21-3216482593-212876407-1992140904-1004 / S-1-11-96-3623454863-58364-18864-2661722203-1597581903-1665606011-1398618912-3018346883-2707767865-2654103518 |
| **Autenticación** | MicrosoftAccount |
| **Privilegio** | BUILTIN\Administradores |
| **Privilegio Crítico** | SeImpersonatePrivilege Habilitada |
| **Nivel Integridad** | High Mandatory Level |
| **MAC Address** | 8A:66:36:F4:79:92 |
| **WiFi SSID** | redopdhcg (WPA2-Personal) |
| **Gateway** | 10.254.0.1 / 10.1.7.254 |
| **IP** | 10.254.117.118 / 10.1.7.238 |

### 6.3 SIDs REGISTRADOS (NGC Credential Provider)

| SID | LogonCredsAvailable | Usuario/Grupo |
|-----|---------------------|---------------|
| S-1-5-21-3216482593-212876407-1992140904-1001 | 2 | Usuario local 1 |
| S-1-5-21-3216482593-212876407-1992140904-1002 | 2 | Usuario local 2 |
| S-1-5-21-3216482593-212876407-1992140904-1004 | 1 | jlangarica@hcg.gob.mx |
| S-1-5-21-3216482593-212876407-1992140904-500 | 2 | Administrator |
| S-1-5-21-3216482593-212876407-1992140904-1008 | N/A | docker-users |

### 6.4 CREDENTIAL PROVIDERS

| GUID | Nombre | Estado |
|------|--------|--------|
| `{01A30791-40AE-4653-AB2E-FD210019AE88}` | Automatic Redeployment Credential Provider | **Disabled** |
| `{48B4E58D-2791-456C-9091-D524C6C706F2}` | Secondary Authentication Factor Credential Provider | **Disabled** |
| `{cb82ea12-9f71-446d-89e1-8d0924e1256e}` | PINLogonProvider | **Disabled** |
| `{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}` | PasswordProvider | Activo |
| `{8AF662BF-65A0-4D0A-A540-A338A999D36F}` | FaceCredentialProvider | Activo |
| `{D6886603-9D2F-4EB2-B667-1971041FA96B}` | NGC Credential Provider | Activo |
| `{F8A1793B-7873-4046-B2A7-1F318747F427}` | FIDO Credential Provider | Activo |
| `{8FD7E19C-3BF7-489B-A72C-846AB3678C96}` | Smartcard Credential Provider | Activo |
| `{BEC09223-B018-416D-A0AC-523971B639F5}` | WinBio Credential Provider | Activo |

### 6.5 GRUPOS DE SEGURIDAD DEL EQUIPO

| Grupo | Tipo | SID | Atributos |
|-------|------|-----|-----------|
| Mandatory Label\High Mandatory Level | Etiqueta | S-1-16-12288 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| Everyone | Grupo conocido | S-1-1-0 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\Cuenta local y miembro del grupo de administradores | Grupo conocido | S-1-5-114 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| 10524DIVSERADMI\docker-users | Alias | S-1-5-21-...-1008 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| BUILTIN\Administradores | Alias | S-1-5-32-544 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado, Propietario de grupo |
| BUILTIN\Usuarios | Alias | S-1-5-32-545 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\INTERACTIVE | Grupo conocido | S-1-5-4 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| CONSOLE LOGON | Grupo conocido | S-1-2-1 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\Authenticated Users | Grupo conocido | S-1-5-11 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\This Organization | Grupo conocido | S-1-5-15 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| MicrosoftAccount\jlangarica@hcg.gob.mx | Usuario | S-1-11-96-... | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\Cuenta local | Grupo conocido | S-1-5-113 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| LOCAL | Grupo conocido | S-1-2-0 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |
| NT AUTHORITY\Autenticación de cuenta de nube | Grupo conocido | S-1-5-64-36 | Grupo obligatorio, Habilitado por defecto, Grupo habilitado |

### 6.6 CREDENCIALES ALMACENADAS

| Target | Type | User | Persistence |
|--------|------|------|-------------|
| MicrosoftAccount SSO POP User | Generic | j3susangar1ca@gmail.com | Session only |
| MicrosoftAccount SSO POP User | Generic | jlangarica@hcg.gob.mx | Session only |
| MicrosoftAccount SSO POP Device | Generic | 02hzmsgfppqadvtv | Session only |
| https://index.docker.io/v1/access-token | Generic | j3susangar1ca | Local machine |
| git:https://github.com | Generic | j3susangar1ca | Local machine |
| https://index.docker.io/v1/refresh-token | Generic | j3susangar1ca | Local machine |
| https://index.docker.io/v1/ | Generic | j3susangar1ca | Local machine |
| MicrosoftAccount j3susangar1ca@gmail.com | Generic | j3susangar1ca@gmail.com | Local machine |
| WindowsLive virtualapp/didlogical | Generic | 02hzmsgfppqadvtv | Local machine |
| Olk/PushNotificationsKey | Generic | Olk/PushNotificationsKey | Local machine |
| MicrosoftAccount jlangarica@hcg.gob.mx | Generic | jlangarica@hcg.gob.mx | Local machine |
| pgAdmin4 | Generic | pgadmin4-master-password | Unspecified |
| 10.2.1.92 | Domain password | 2020205 | Local machine |
| Anytype/A6ZUzXWuozZsVKX58QGJFin2LBix99j9xvP659FTbe6uaxu2 | Generic | A6ZUzXWuozZsVKX58QGJFin2LBix99j9xvP659FTbe6uaxu2 | Unspecified |

### 6.7 CREDENCIALES POR DEFECTO COMPROMETIDAS (MorphoManager)

| Servicio | Usuario | Contraseña | Estado |
|----------|---------|------------|--------|
| Consola Web | admin | admin | CONFIRMADO |
| Servicio SOAP | morpho | morpho | CONFIRMADO |
| SQL Server | sa | Morpho@123 | CONFIRMADO |
| Windows Service | service | service | CONFIRMADO |

### 6.8 MÉTODOS DE AUTENTICACIÓN

| Método | Contexto | Vulnerabilidad |
|--------|----------|----------------|
| NTLMv2 | Windows Network | Vulnerable a robo de hashes/Relay |
| WPA2-Personal | Wi-Fi (SSID: redopdhcg) | PSK |
| SOAP sin WSS/TLS | MorphoManager | HTTP plano detectado |
| Active Directory | Dominio opd-hcg.org | Domain User detectado via SRV |

### 6.9 VULNERABILIDADES DE IAM

| Vulnerabilidad | Descripción |
|----------------|-------------|
| Cookies sin prefijo __Host- | Drupal Session Hijacking posible |
| Session ID expuesto | Cabeceras Set-Cookie visibles |
| WPAD detectado | Vulnerable a envenenamiento WPAD |

### 6.10 POLÍTICAS DE SEGURIDAD

| Política | Estado |
|----------|--------|
| AppLocker (Kernel) | Aplicado |
| AppLocker (Usuario) | Desactivado |
| BitLocker (BDESVC) | Manual, Detenido |

### 6.11 PROCESOS EN EJECUCIÓN MONITOREADOS

| PID | Name | Path | Description |
|-----|------|------|-------------|
| 17136 | chrome | C:\Program Files\Google\Chrome\Application\chrome.exe | Google Chrome |
| 11424 | explorer | C:\WINDOWS\Explorer.EXE | Explorador de Windows |
| 4860 | OneDrive | C:\Program Files\Microsoft OneDrive\OneDrive.exe | Microsoft OneDrive |
| 35064 | remoting_host | C:\Program Files (x86)\Google\Chrome Remote Desktop\146.0.7680.5\remoting_host.exe | Chrome Remote Desktop Host |
| 5824 | svchost | C:\WINDOWS\system32\svchost.exe | Proceso host de servicio de Windows |

### 6.12 REDES WI-FI DETECTADAS

| SSID | Auth | Cifrado | Señal | Banda | Canal |
|------|------|---------|-------|-------|-------|
| redopdhcg | WPA2-Personal | CCMP | 75-87% | 2.4/5 GHz | 1, 6, 11, 36, 52, 116, 128, 149 |
| INFINITUM4391 | WPA2-Personal | CCMP | 80-87% | 2.4/5 GHz | 11, 132 |
| ATT_Internet_En_Casa_9002 | WPA2-Personal | CCMP | 75% | 2.4 GHz | 7 |
| Linksys01282 | WPA2-Personal | CCMP | 60% | 2.4/5 GHz | 9, 36 |
| IZZI-3369-5G | WPA2-Personal | CCMP | 40% | 5 GHz | 40 |
| izziPiso 1 T/Vesp-5G | WPA2-Personal | CCMP | 43% | 5 GHz | 40 |
| DIRECT-3a-HP M203 LaserJet | WPA2-Personal | CCMP | 33% | 2.4 GHz | 6 |
| DIRECT-B4-EPSON-M2170 Series | WPA2-Personal | CCMP | 60% | 2.4 GHz | 11 |
| (Hidden SSID) | WPA2-Personal | CCMP | 40% | 5 GHz | 40 |

#### Detalle de redopdhcg (Red Institucional) por Access Point

| BSSID | Señal | Banda | Canal | Tipo | Estaciones |
|-------|-------|-------|-------|------|------------|
| f4:45:88:7a:8a:50 | 75% | 5 GHz | 52 | 802.11be | 29 |
| 08:fa:28:59:09:40 | 50% | 5 GHz | 52 | 802.11ax | 44 |
| b8:85:7b:28:e6:e0 | 80% | 2.4 GHz | 1 | 802.11be | 1 |
| f4:45:88:7a:72:00 | 83% | 2.4 GHz | 6 | 802.11be | 3 |
| f4:45:88:f8:37:10 | 40% | 5 GHz | 149 | 802.11be | 8 |
| b8:85:7b:28:e6:f0 | 62% | 5 GHz | 116 | 802.11be | 8 |
| c4:5e:5c:24:79:20 | 57% | 2.4 GHz | 11 | 802.11ax | 6 |
| b8:85:7b:28:e1:70 | 57% | 5 GHz | 128 | 802.11be | 12 |
| f4:45:88:7a:72:10 | 78% | 5 GHz | 36 | 802.11be | 16 |
| f4:45:88:7a:8a:40 | 85% | 2.4 GHz | 11 | 802.11be | 5 |

**Autenticación:** WPA2-Personal  
**Cifrado:** CCMP

### 6.13 PERFIL WI-FI GUARDADO (redopdhcg)

| Parámetro | Valor |
|-----------|-------|
| Profile GUID | {1C71CCF1-6CE4-4ADB-8F74-1B277DF7AE56} |
| Profile Index | 0x10000001 |
| Has Connected | Sí |
| Security Descriptor | O:SYG:SYD:(A;;CCRC;;;BU)(A;;CCRC;;;NO)... |
| Band Channel Hints | Canales 1, 6, 11, 36, 52, 116, 128, 149 |
| MAC Randomization | Habilitado |

### 6.14 Permisos WLAN API

| Permiso | SDDL |
|---------|------|
| Permit List | O:SYG:SYD:(A;;CCRC;;;BU)(A;;CCRC;;;NO)(A;;CCDCWPSDRCWD;;;NO)(A;;CCRC;;;BA)(A;;CCDCWPSDRCWD;;;BA)(D;;FA;;;WD) |
| Deny List | O:SYG:SYD:(A;;CCRC;;;BU)(A;;CCRC;;;NO)(A;;CCDCWPSDRCWD;;;NO)(A;;CCRC;;;BA)(A;;CCDCWPSDRCWD;;;BA)(D;;FA;;;WD) |
| Get Plain Text Key | O:SYG:SYD:(A;;CCRC;;;BA)(A;;CCRC;;;NO)(A;;CCRC;;;SY)(D;;FA;;;WD) |

---

## [SECCIÓN 7: VULNERABILIDADES CVE]

### 7.1 Resumen de CVEs por Severidad

| Severidad | Count | Porcentaje |
|-----------|-------|------------|
| **CRITICAL (9.0-10.0)** | 6 | 24% |
| **HIGH (7.0-8.9)** | 12 | 48% |
| **MEDIUM (4.0-6.9)** | 6 | 24% |
| **LOW (0.0-3.9)** | 1 | 4% |
| **TOTAL** | 25 | 100% |

### 7.2 Catálogo Completo de CVE

| CVE | CVSS | Componente | Descripción | Tipo |
|-----|------|------------|-------------|------|
| CVE-2019-9569 | 9.8 | Delta Controls dactetra | Buffer overflow en demonio BACnet | RCE |
| CVE-2019-11043 | 9.8 | PHP-FPM | RCE vía env_path_info | RCE |
| CVE-2024-38474 | 9.8 | Apache mod_rewrite | RCE mediante encoding sustituciones | RCE |
| CVE-2025-55315 | 9.9 | Kestrel/ASP.NET | Request Smuggling, bypass WAF | Movement |
| CVE-2025-59775 | N/A | Windows | SSRF con fuga NTLMv2 a UNC | Exfiltration |
| CVE-2020-1938 | N/A | Tomcat AJP | Ghostcat - lectura archivos/RCE | RCE |
| CVE-2019-0205 | N/A | Apache Thrift | Deserialización insegura | RCE |
| CVE-2021-33742 | N/A | Firmware Update | RCE sin validación firma | RCE |
| CVE-2021-44228 | 10.0 | Log4j | Log4Shell (potencial en SOAP/Java) | RCE |
| CVE-2020-1350 | 10.0 | DNS | SIGRed (si DNS expuesto) | RCE |
| CVE-2019-0211 | 9.8 | Apache | Privilege Escalation | PE |
| CVE-2020-1938 | 9.8 | Tomcat AJP | Ghostcat - RCE/File Read | RCE |

### 7.3 Matriz de Activos vs CVE

| Activo | CVEs Aplicables |
|--------|-----------------|
| ACTIVO-WEB-01 | CVE-2019-11043, CVE-2024-38474, CVE-2025-59775, CVE-2025-55315, CVE-2019-0211 |
| ACTIVO-ICS-01 | CVE-2019-9569 |
| ACTIVO-INTERNAL-TOMCAT | CVE-2020-1938 |
| MorphoManager | CVE-2019-0205, CVE-2021-33742, CVE-2021-44228 |

### 7.4 Vulnerabilidades sin CVE (Misconfigurations)

| Host | Vulnerabilidad | Impacto |
|------|----------------|---------|
| www.hcg.gob.mx | Server header version leak | Information Disclosure |
| www.hcg.gob.mx | SOCKS5/Tor detected | Possible prior compromise |
| 10.254.117.118 / 10.1.7.238 | SeImpersonatePrivilege | Privilege Escalation |
| 10.254.117.118 | WPA2-Personal | Wi-Fi compromise |
| 10.254.x.x | AJP13 exposed | RCE/File Read |
| lajun.hosting-mexico.net | cPanel public | Brute-force |
| 10.2.1.140 | RDP/SMB internal | Lateral Movement |
| 10.2.1.1 | LDAP unencrypted | Credential theft |
| 10.1.7.97 | SMBv1/v2 potencial | Legacy protocol |

---

## [SECCIÓN 8: MATRIZ MITRE ATT&CK]

| Táctica | Técnica ID | Nombre | Hosts Afectados | Prioridad |
|---------|------------|--------|-----------------|-----------|
| Initial Access | T1190 | Exploit Public-Facing Application | www.hcg.gob.mx | CRÍTICA |
| Initial Access | T1078 | Valid Accounts | 10.254.117.118, 10.1.7.238 | ALTA |
| Execution | T1059 | Command and Scripting Interpreter | Todos Windows | CRÍTICA |
| Privilege Escalation | T1134.001 | Token Impersonation | 10.254.117.118, 10.1.7.238 | CRÍTICA |
| Credential Access | T1003 | OS Credential Dumping | Todos Windows | CRÍTICA |
| Credential Access | T1558.003 | Kerberoasting | 10.2.1.1 (DC) | ALTA |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | 10.2.1.140 | ALTA |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | 10.2.1.140, 10.2.1.92 | ALTA |
| Collection | T1005 | Data from Local System | sigma.hcg.gob.mx | CRÍTICA |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Todos | CRÍTICA |
| Impact | T1486 | Data Encrypted for Impact | Todos | CRÍTICA |

---

## [SECCIÓN 9: CONFLICTOS DE DATOS]

### Conflicto #1: Puertos de Servicio MorphoManager

| Versión | Thrift RPC | SOAP API | Updates |
|---------|------------|----------|---------|
| A (Estándar) | TCP 11010 | TCP 42100 | TCP 11001 |
| B (Script) | TCP 42101 | TCP 42100 | TCP 42102 |

**Estado:** [DATO_PENDIENTE_DE_CONFIRMACIÓN] - Ambas versiones documentadas

### Conflicto #2: IP de Gateway

| Fuente | IP Gateway | Contexto |
|--------|------------|----------|
| network_config.txt | 192.168.137.1 | Interfaz virtual/Hotspot |
| ipconfig.txt | 10.1.7.254 | Subred principal IT |

**Estado:** RESUELTO - Ambas son válidas según interfaz

### Conflicto #3: IP del Host Origen

| Fuente | IP | Contexto |
|--------|-----|----------|
| MIC v1.0 | 10.254.117.118 | WiFi Client |
| MIC v3.0 | 10.1.7.238 | Ethernet Principal |

**Estado:** RESUELTO - Ambas son válidas según interfaz utilizada

### Conflicto #4: Driver Version Wi-Fi

| Fuente | Versión | Fecha |
|--------|---------|-------|
| vmsswitch.md | 20.70.0030.0001 | 9/22/2022 |
| Informe Final | 22.160.0.4 | 14/08/2022 |

**Estado:** RESUELTO - Posible actualización de driver entre auditorías

---

## EVIDENCIA FORENSE RECOPILADA

| Host | Tipo | Detalle | Implicación |
|------|------|---------|-------------|
| www.hcg.gob.mx | Critical Artifact | SOCKS5 proxy en 127.0.0.1:9050 (Tor) | Posible compromiso previo |
| 10.254.117.118 / 10.1.7.238 | Exposed Secret | SID S-1-5-21-3216482593-212876407-1992140904-1004 | Identidad para ataques |
| 10.254.117.118 / 10.1.7.238 | Critical Artifact | MAC Address: 8A:66:36:F4:79:92 | Identificación física |
| 10.254.117.118 / 10.1.7.238 | Critical Artifact | Wi-Fi SSID: redopdhcg (WPA2-Personal) | Vector inalámbrico |
| 10.254.117.118 / 10.1.7.238 | Critical Artifact | SeImpersonatePrivilege Habilitada | Escalada garantizada |
| 10.254.117.118 / 10.1.7.238 | Privilege Level | BUILTIN\Administradores (jlangarica@hcg.gob.mx) | Credencial alto valor |

---

**FIN DEL MAPA DE INFRAESTRUCTURA CENTRALIZADO**

---
*Documento generado por Infrastructure Integrity Auditor*  
*Clasificación: CONFIDENCIAL / RED TEAM OPERATIONS*  
*Versión: 4.0 - CONSOLIDACIÓN FINAL INTEGRADA*

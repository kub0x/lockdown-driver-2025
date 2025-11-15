# Requisitos:

## DebugView

- Descargar DebugView https://learn.microsoft.com/en-us/sysinternals/downloads/debugview
- Abrir el binario de 32 bit corriendo como Administrador
- Habilitar Capture Kernel
- Habilitar Enable Verbose Kernel Output
## Visual Studio + Kit WDM (Desarrollo de drivers)

- Seguir los pasos de https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

## Instalación driver

Ubicar el driver .sys y copiarlo a un origen conocido.

Manualmente desde una consola que corre como Administrador instalar el driver .sys creando un servicio. sc.exe nos ayuda con esto:

**sc create Lockdown type= kernel start= demand binPath= "path-del-driver-sys" DisplayName= lockdown**

## Notas:

- Al crear un proyecto WDM, éste viene con un archivo .INF de instalación.
- La solución no compila por defecto. Se debe eliminar el .INF
- El driver de ejemplo Lockdown no trae el .INF por esta razón
# Reglas del Proyecto

## Memoria
CODEBASE_SUMMARY.md contiene la estructura completa de este proyecto.
CHANGELOG_CONTEXT.md contiene los cambios recientes.
Ambos archivos están en la raíz y son tu fuente de verdad.

## Reglas de eficiencia (OBLIGATORIAS)

### PROHIBIDO:
- Usar find, grep recursivo, o listados de directorios para "entender el proyecto"
- Leer más de 3 archivos antes de empezar a trabajar
- Explorar node_modules, dist, build, .git, vendor, __pycache__
- Leer package.json o archivos de config a menos que la tarea sea modificarlos
- Pedir contexto adicional si CODEBASE_SUMMARY.md tiene la respuesta

### OBLIGATORIO:
1. Leer CODEBASE_SUMMARY.md al inicio de cada tarea
2. Leer CHANGELOG_CONTEXT.md si necesitas contexto de cambios recientes
3. Identificar el archivo exacto a modificar ANTES de leerlo
4. Leer SOLO archivos directamente necesarios
5. Si creas carpetas/archivos clave o cambias dependencias → actualizar CODEBASE_SUMMARY.md
6. Si haces un cambio significativo → añadir entrada en CHANGELOG_CONTEXT.md

### Flujo de trabajo:
Tarea → Leer CODEBASE_SUMMARY.md → Identificar archivo → Leer SOLO ese archivo → Ejecutar → Actualizar memoria si hubo cambios

### Formato de respuestas:
- Conciso. Código primero, explicación mínima después.
- No repitas código que no modificaste.
- Muestra solo los bloques cambiados con contexto suficiente.

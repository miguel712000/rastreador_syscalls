# Rastreador de Syscalls en Rust

Este es un rastreador de **syscalls** que utiliza `ptrace` para interceptar y monitorear las llamadas del sistema de un proceso hijo.

## Instrucciones

### Instalación
1. Clona el repositorio:
```bash
git clone https://github.com/tu_usuario/rastreador_syscalls.git
cd rastreador_syscalls
```

2. Compila el proyecto:
```bash
cargo build --release
```

3. Ejecuta el rastreador:
```bash
./target/release/rastreador_syscalls [opciones] <programa> [argumentos]
```

---

## Uso

### Ejecución Básica
```bash
./rastreador_syscalls ls
```

### Modo Verboso
```bash
./rastreador_syscalls -v ls
```

### Modo Pausa
```bash
./rastreador_syscalls -V ls
```

---

## Ejemplo de Salida
```bash
Ejecutando ls con PID: 12345
Syscall detectada: 257 (openat)
Syscall detectada: 262 (newfstatat)
Syscall detectada: 1 (write)
Syscall detectada: 3 (close)

Resumen de Syscalls:
Syscall 257 (openat): 2 veces
Syscall 262 (newfstatat): 4 veces
Syscall 1 (write): 10 veces
Syscall 3 (close): 5 veces
```

---

## Dependencias
- `nix` para interacción con ptrace.
Instálala con:
```bash
cargo add nix
```

---

##  Opciones
| Opción | Descripción              |
|--------|--------------------------|
| `-v`   | Modo verboso              |
| `-V`   | Pausa tras cada syscall   |

---

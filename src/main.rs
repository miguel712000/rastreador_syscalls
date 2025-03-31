use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use nix::unistd::Pid;
use std::env;
use std::ffi::CString;
use std::process;
use std::io::{self, Write};
use std::collections::HashMap;

// Función para mapear números de syscalls a nombres conocidos
fn get_syscall_name(syscall_num: u64) -> &'static str {
    let syscall_map: HashMap<u64, &str> = [
        (0, "read"),
        (1, "write"),
        (2, "open"),
        (3, "close"),
        (4, "stat"),
        (5, "fstat"),
        (6, "lstat"),
        (8, "creat"),
        (9, "mmap"),
        (10, "mprotect"),
        (11, "munmap"),
        (12, "brk"),
        (16, "ioctl"),
        (17, "pread64"),
        (21, "access"),
        (41, "socket"),
        (42, "connect"),
        (59, "execve"),
        (137, "sendfile"),
        (158, "arch_prctl"),
        (191, "getsockname"),
        (192, "getpeername"),
        (217, "ftruncate"),
        (218, "fstatfs"),
        (231, "exit_group"),
        (257, "openat"),
        (262, "newfstatat"),
        (273, "preadv"),
        (302, "futex"),
        (318, "mlock2"),
        (332, "statx"),
        (334, "pkey_alloc"),
    ]
    .iter()
    .cloned()
    .collect();

    // Si no se encuentra el número de syscall, devolver "unknown_syscall"
    syscall_map.get(&syscall_num).copied().unwrap_or("unknown_syscall")
}

// Función principal para rastrear syscalls
fn main() {
    // Obtiene los argumentos de la línea de comandos
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Uso: ./rastreador [opciones rastreador] Prog [opciones de Prog]");
        process::exit(1);
    }

    // Manejo de opciones de rastreador (-v para verbose, -V para pausa)
    let mut verbose = false;
    let mut pause = false;
    let mut prog_index = 1;

    for i in 1..args.len() {
        if args[i] == "-v" {
            verbose = true;
        } else if args[i] == "-V" {
            pause = true;
        } else {
            prog_index = i;
            break;
        }
    }

    // Si no hay programa a ejecutar, salir con error
    if prog_index >= args.len() {
        eprintln!("Error: No se especificó un programa a ejecutar.");
        process::exit(1);
    }

    // Obtiene el programa y sus argumentos para ejecutarlo
    let prog = &args[prog_index];
    let prog_args: Vec<CString> = args[prog_index..]
        .iter()
        .map(|arg| CString::new(arg.clone()).unwrap())
        .collect();

    // Creación del proceso hijo usando fork
    match unsafe { fork() } {
        // Proceso hijo
        Ok(ForkResult::Child) => {
            // Habilita ptrace para rastrear el proceso hijo
            ptrace::traceme().expect("Error al activar ptrace en el hijo");
            // Ejecuta el programa especificado
            execvp(&prog_args[0], &prog_args).expect("Error al ejecutar el programa");
        }

        // Proceso padre (rastreador)
        Ok(ForkResult::Parent { child }) => {
            println!("Ejecutando {} con PID: {}", prog, child);

            // Inicializar el contador de syscalls
            let mut syscallCount: HashMap<u64, u64> = HashMap::new();

            // Bucle principal para rastrear el proceso hijo
            loop {
                match waitpid(child, None) {
                    // Si el proceso hijo terminó normalmente
                    Ok(WaitStatus::Exited(_, status)) => {
                        println!("Proceso finalizado con código: {}", status);
                        mostrar_resumen(&syscallCount);
                        break;
                    }

                    // Si el proceso hijo terminó debido a una señal
                    Ok(WaitStatus::Signaled(_, signal, _)) => {
                        println!("Proceso terminado por señal: {:?}", signal);
                        break;
                    }

                    // Si el proceso hijo está detenido debido a una señal (ej. SIGTRAP)
                    Ok(WaitStatus::Stopped(pid, signal)) => {
                        if signal == nix::sys::signal::Signal::SIGTRAP {
                            // Muestra la syscall si -v o -V fueron activados
                            if verbose || pause {
                                mostrar_syscall(pid, &mut syscallCount);
                            }

                            // Si la opción -V está habilitada, esperar input del usuario
                            if pause {
                                println!("Presiona Enter para continuar...");
                                let _ = io::stdin().read_line(&mut String::new());
                            }
                            // Continuar el rastreo
                            ptrace::syscall(pid, None).expect("Error al continuar rastreo");
                        } else {
                            // Continúa la ejecución si no es SIGTRAP
                            ptrace::cont(pid, None).expect("Error al continuar ejecución");
                        }
                    }

                    // Si el proceso interceptó una syscall
                    Ok(WaitStatus::PtraceSyscall(pid)) => {
                        if verbose || pause {
                            mostrar_syscall(pid, &mut syscallCount);
                        }

                        if pause {
                            println!("Presiona Enter para continuar...");
                            let _ = io::stdin().read_line(&mut String::new());
                        }

                        // Continuar rastreo después de la syscall
                        ptrace::syscall(pid, None).expect("Error al continuar rastreo");
                    }

                    // Manejar otros casos no considerados explícitamente
                    Ok(_) => {
                        ptrace::syscall(child, None).expect("Error al continuar rastreo");
                    }

                    // Si hay error al esperar al proceso hijo
                    Err(e) => {
                        eprintln!("Error al esperar al hijo: {:?}", e);
                        break;
                    }
                }
            }
        }

        // Si hay error al crear el proceso hijo
        Err(_) => {
            eprintln!("Error al crear el proceso hijo.");
            process::exit(1);
        }
    }
}

// Función para mostrar y registrar la syscall interceptada
fn mostrar_syscall(pid: Pid, syscallCount: &mut HashMap<u64, u64>) {
    match ptrace::getregs(pid) {
        Ok(regs) => {
            let syscallNum = regs.orig_rax;
            // Actualiza el contador de syscalls
            *syscallCount.entry(syscallNum).or_insert(0) += 1;

            // Muestra la syscall detectada
            println!(
                "Syscall detectada: {} ({})",
                syscallNum,
                get_syscall_name(syscallNum)
            );
        }
        Err(err) => {
            eprintln!("Error al obtener registros: {:?}", err);
            process::exit(1);
        }
    }
}

// Función para mostrar resumen final de syscalls detectadas
fn mostrar_resumen(syscallCount: &HashMap<u64, u64>) {
    println!("\nResumen de Syscalls:");
    for (syscallNum, count) in syscallCount {
        let syscallName = get_syscall_name(*syscallNum);
        println!("Syscall {} ({}): {} veces", syscallNum, syscallName, count);
    }
}

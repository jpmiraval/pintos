#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"
#include "../filesys/file.h"  
#include "../filesys/filesys.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);

struct  fdDetails{
  /*Puntero fd original*/
  int fd;
  /*Nombre del file*/
  char* file_name;
  /*Puntero a mi mismo*/
  struct file* file_ptr;
  struct list_elem elem;
};

struct fdDetails* getFile(int fd){
  struct thread* current_thread = thread_current();
  struct list_elem* e;

  for (e = list_begin (&current_thread->thread_files); e != list_end (&current_thread->thread_files); e = list_next (e)){
    struct  fdDetails *current_fd = list_entry (e, struct fdDetails, elem);
    if (fd == current_fd -> fd){
      return current_fd;
    }
  }
  return NULL;

}

struct thread* hijos (int processID){
  struct list_elem* e;
  for (e = list_begin (&thread_current()->t_children); e != list_end (&thread_current()->t_children);
       e = list_next (e))
    {
      struct thread *child_current = list_entry (e, struct thread, child_elem);
      if (child_current->tid == processID)
        return child_current;
    }
  return NULL;
}

void funct_exit (int status){

  /*Marcamos el exit status del thread*/
  thread_current()->exit_status = status;
  
  /*Liberamos todos los files del thread*/
  while (!list_empty(&thread_current()->thread_files)){
    /*Recuperamos el siguiente file de la lista de files*/
    struct list_elem* e = list_pop_front (&thread_current()->thread_files);
    struct fdDetails *fdCurrent = list_entry(e, struct fdDetails, elem);
    /*Cerramos el file_ptr*/
    file_close(fdCurrent->file_ptr);
    free(fdCurrent);
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}


void es_valido(void* espacio, unsigned size){
  /*Verificamos que el puntero no sea vacío*/
  if (espacio == NULL) funct_exit(-1);
  /*Verificamos que cada bit no sea inválido*/
  for (int i = 0; i < size; i++){
    void* puntero = (void*)((uint8_t*)espacio+i);
    /*Verificamos que el puntero exista, que no sea el user virtual adress y que se encuentre en espacio de usuario*/
    if(!puntero || !is_user_vaddr(puntero) || puntero < (void*) 0x08048000)
      funct_exit(-1);
    if (pagedir_get_page(thread_current()->pagedir, puntero) == NULL)
      funct_exit(-1);
  }
}

void string_valida(void* espacio){
  /*Verificamos que el puntero no sea vacío*/
  if (espacio == NULL) funct_exit(-1);
  char* string = (char*)espacio;
  /*Verificamos si cada char es válido*/
  for (; string != '\0'; string++){
    void* puntero = (void*)(string);
    /*Verificamos que el puntero exista, que no sea el user virtual adress y que se encuentre en espacio de usuario*/
    if(!puntero || !is_user_vaddr(puntero) || puntero < (void*) 0x08048000)
      funct_exit(-1);
    if (pagedir_get_page(thread_current()->pagedir, puntero) == NULL)
      funct_exit(-1);
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* ################## */
/* ################## */

/* FUNCIONES INTERNAS */
/* Funct exit está arriba */

void funct_halt (void){
  /* Kill Pintos */
  shutdown_power_off();
}

int funct_wait (int pid){
  return process_wait(pid);
}

int funct_exec (const char *command){
  /*Parseamos el nombre del archivo. Si existe, creamos un hijo, esperamos a que cargue y ejecutamos*/
  /* retornamos pid del hijo si todo sale bien, sino -1 */
  lock_acquire(&syscall_lock);
  /* Copia para parsear el filename y args*/
  char fileCopy[200];
  strlcpy(fileCopy, command, strlen(command)+1);

  /* Parseamos filename */
  char* token;
  char* save_ptr;
  token = strtok_r (fileCopy, " ", &save_ptr);

  /* vemos si el file existe */
  struct file* file_test = filesys_open(token);
  if (file_test == NULL){
    /* si existe quitamos el lock */
    lock_release(&syscall_lock);
    return -1;
  }
  /* cerramos file */
  file_close(file_test);
  lock_release(&syscall_lock);

  /* hacemos return si el execute devuelve -1 */
  int processID = process_execute(command);
  if (processID == -1){
    return processID;
  }

  /* bsucamos al child */
  struct thread* child = hijos (processID);
  if (child == NULL){
    return -1;
  }

  /* esperamos a que el child cargue */
  while (child->exec_status == LOADING)
    thread_yield();

  /* Si falilea, gg */
  if (child->exec_status == LOADING_FAIL){
    return -1;
  }

  /* retornamos process ID del proceso resultante*/
  return processID;
}

  bool funct_create (const char *filename, unsigned size){
    /* Si es nulo, kill */
    if  (filename == NULL)
      funct_exit(-1);
    /* creamos archivo con el tamaño indicado */
    lock_acquire(&syscall_lock);
    bool created = filesys_create(filename, size);
    lock_release(&syscall_lock);
    return created;
  }

  bool funct_remove (const char *filename){
    /*Se elimina un archivo mediante el filesys*/
    lock_acquire(&syscall_lock);
    bool deleted = filesys_remove(filename);
    lock_release(&syscall_lock);
    return deleted;
  }

  int funct_open (const char* filename){
    /*Si es nulo, kill*/
    if (filename == NULL)
      funct_exit(-1);
    lock_acquire(&syscall_lock);
    struct file* file_temp = filesys_open (filename);
    int fd = -1;

    if (file_temp){
      /* Alocamos el fdDetails para este archivo que abrimos */
      struct fdDetails *newFile = malloc(sizeof(struct fdDetails));
      /* Obtenemos el nuevo fd que se le asignará */
      fd = thread_current()->nextfd++;
      /* Actualizamos los details del fdDetails */
      newFile->fd = fd;
      newFile->file_name = filename;
      newFile->file_ptr = file_temp;
      /* INsertamos el file en el array de files del thread */
      list_push_back(&thread_current()->thread_files, &newFile->elem);
    }
    lock_release(&syscall_lock);
  }

  int funct_filesize (int fd){
    /* Variable donde guardaremoslongitud */
    int size = 0;
    lock_acquire(&syscall_lock);
    /* Buscamos el file según su fd */
    struct fdDetails *file_temp = getFile(fd);

    if (file_temp){
      if (!(file_temp->file_ptr))
        funct_exit(-1);
      /* Si podemosabrir el archivo sin problemas, sacamos el tamaño del propio archivo */
      size = file_length(file_temp->file_ptr);
    }
    lock_release(&syscall_lock);
    return size;
  }

  int funct_read (int fd, void *espacio, unsigned size){
    /* Contaremos los bytes que se han ido leyendo*/
    int bytes_read = 0;
    lock_acquire(&syscall_lock);

    if (!fd){
      /*Si el fd es 0, se pedirá stdin desde la consola*/
      while(size){
        int input = input_getc();
        if (!input) break;
        bytes_read += 1;
        size--;
      }

    } else {
      struct fdDetails *file_temp = getFile(fd);

      if (file_temp){
        if (!(file_temp))
          funct_exit(-1);
        bytes_read = file_read(file_temp->file_ptr, espacio, size);
      } else {
        /* si no se puede leer, se retrna -1 */
        bytes_read = -1;
      }

    }
    lock_release(&syscall_lock);
    return bytes_read;
  }

  int funct_write (int fd, const void *espacio, unsigned size){
    /* Similar al read, pero con operaciones de escritura */
    /* Almacenamos cuantos bytes escribiremos */
    int bytes_written = 0;
    lock_acquire(&syscall_lock);
    /* si fd es 1 es que se imprime en consola */
    if (fd == 1){
      putbuf (espacio, size);
      bytes_written = size;
    } else {
      struct fdDetails *file_temp = getFile(fd);

      if (file_temp) {
        /*Si el file no existe, kill*/
        if (!(file_temp->file_ptr))
          funct_exit(-1);
        /* Se escribe y se guarda cuántos bytes se escribieron */
        bytes_written = file_write(file_temp->file_ptr, espacio, size);
      }
      else
        bytes_written = 0;
    }
    lock_release(&syscall_lock);
    return bytes_written;
  }  

  void funct_seek (int fd, unsigned position){
    lock_acquire(&syscall_lock);
    /* Cargamos el file donde estamos */
    struct fdDetails *file_temp = getFile(fd);
  /*Verificamos que exista, sino kill*/
  if (file_temp){
    if (!(file_temp->file_ptr))
      funct_exit(-1);
    /*hacemos el file seek*/
    file_seek(file_temp->file_ptr, position);
  }
  lock_release(&syscall_lock);
  }

  unsigned funct_tell (int fd){
    /* Usaremos el file tell, proceso similar a los anteriores */
    unsigned tell = 0;
    lock_acquire(&syscall_lock);
    struct fdDetails *file_temp = getFile(fd);

    if(file_temp){
      if (!(file_temp->file_ptr))
        funct_exit(-1);
      tell = file_tell(file_temp->file_ptr);
    }
    lock_release(&syscall_lock);
    return tell;
  }

  void funct_close (int fd){
    lock_acquire(&syscall_lock);
    /* Buscamos el file*/
    struct fdDetails *file_temp = getFile(fd);

    if (file_temp){
      /* si no existe, kill*/
      if (!(file_temp->file_ptr))
        funct_exit(-1);
      /* cerramos file y lo sacamos de la lista*/
      file_close(file_temp->file_ptr);
      list_remove(&(file_temp->elem));
      free(file_temp);
    }
    lock_release(&syscall_lock);
  }





/* ################## */
/* ################## */


/* ################## */
/* ################## */

/* SYSCALL HANDLER */


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /*Primero tenemos que revisar si el puntero superior de f es válido*/
  es_valido(f->esp, sizeof(int));

  /*interpretamos los syscalls*/
  /*Aquí parseamos los SYSCALLS nomás, luego llamamos a las funciones internas*/
  /*Básicamente verificamos que los punteros sean válidos y parseamos la data necesaria para llamar a las funciones */
  switch(*(int*)f->esp){
    case SYS_HALT:{
      /*invocamos el halt*/
      funct_halt();
      break;
    }
    case SYS_EXIT:{
      /*verificamos que el puntero sea válido*/
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /*Llamaremos a la función exit pasando el estado*/
      int estado = *((int*)f->esp + 1 );
      funct_exit(estado);
      break;
    }
    case SYS_EXEC:{
      /*Validamos los punteros en esp+1*/
      /*En realidad, la función string_valida hace lo mismo que es_valido, solo que para strings*/
      string_valida((void*)(*((int*)f->esp+1)));

      const char* comando = (char*)(*((int*)f->esp + 1));
      f->eax = funct_exec(comando);
      break;
    }
    case SYS_WAIT:{
      /*Validamos puntero*/
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      int pid = *((int*)f->esp + 1 );
      f->eax = funct_wait(pid);
      break;
    }
    case SYS_CREATE:{
      /*Creamos file*/
      /*Validando punteros en esp+1 y +2*/
      string_valida((void*)(*((int*)f->esp + 1)));
      es_valido((void*)(((unsigned*)f->esp + 2)), sizeof(int));
      /*nombre de file*/
      const char* file = (char*)(*((int*)f->esp + 1 ));
      /*Estado*/
      unsigned initial_size = *((unsigned*)f->esp + 2);
      f->eax = funct_create(file, initial_size);
      break;
    }
    case SYS_REMOVE:{
      /*Borramos file*/
      /*Verificamos puntero*/
      string_valida((void*)(*((int*)f->esp + 1)));
      /*Parseamos name*/
      const char* file = (char*)(*((int*)f->esp + 1 ));
      f->eax = funct_remove(file);
      break;
    }
    case SYS_OPEN:{
      /* Abrimos file. */
      /* Validamos puntero */
      string_valida((void*)(*((int*)f->esp + 1)));
      /* Parseamos name*/
      const char* file = (char*)(*((int*)f->esp + 1 ));
      /*Almacenamos en eax*/
      f->eax = funct_open(file);
      break;
    }
    case SYS_FILESIZE:{
      /* Obtengo file's size. */
      /* Valido puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* Parseo fd */
      int fd = *((int*)f->esp + 1 );
      f->eax = funct_filesize(fd);
      break;
    }
    case SYS_READ:{
      /* Leer file. */
      /* Verificamos puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* parseamos fd */
      int fd = *((int*)f->esp + 1);
      /* Verificamos puntero +3*/
      es_valido((void*)(((unsigned*)f->esp + 3)), sizeof(int));
      /* Parseamos tamaño */
      unsigned size = *((unsigned*)f->esp + 3);
      /* Verificamos puntero en +2 */
      es_valido((void*)(*((int*)f->esp + 2)), size);
      /* Parseamos elbuffer */
      void * buffer = (void*)(*((int*)f->esp + 2));
      f->eax = funct_read(fd, buffer, size);
      break;
    }
    case SYS_WRITE:{
      /* Escribir file. */
      /* Validamos puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* Parseamos fd */
      int fd = *((int*)f->esp + 1);
      /* Validamos siguiente puntero */
      es_valido((void*)(((unsigned*)f->esp + 3)), sizeof(int));
      /* Parseamos tamaño */
      unsigned size = *((unsigned*)f->esp + 3);
      /* Validamos siguiente puntero */
      es_valido((void*)(*((int*)f->esp + 2)), size);
      /* Parseamos buffer */
      void * buffer = (void*)(*((int*)f->esp + 2));
      f->eax = funct_write(fd, buffer, size);
      break;
    }
    case SYS_SEEK:{
      /* Cambiamos lector|puntero|posicion en un file. */
      /* Validamos puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* Validamos siguiente puntero */
      es_valido((void*)(((unsigned*)f->esp + 2)), sizeof(int));
      /* Parseamos fd */
      int fd = *((int*)f->esp + 1);
      /* Parseamos posicion */
      unsigned position = *((unsigned*)f->esp + 2);
      funct_seek(fd, position);
      break;
    }
    case SYS_TELL:{
      /* Report posicion en file. */
      /* Validamos puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* Parseamos fd */
      int fd = *((int*)f->esp + 1);
      f->eax = funct_tell(fd);
      break;
    }
    case SYS_CLOSE:{
      /* Cerrar */
      /* Validamos puntero */
      es_valido((void*)(((int*)f->esp + 1)), sizeof(int));
      /* Parseamos fd */
      int fd = *((int*)f->esp + 1);
      funct_close(fd);
      break;
    }


  }
  /*printf ("system call!\n");*/
  thread_exit ();
}

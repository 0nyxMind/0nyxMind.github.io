---
title: Conceptos básicos de Stack Buffer Overflow
categories: [Explotación de binarios]
image: BufferOverflow.png
img_path: /assets/Cursos/BufferOverflow/
---

Bienvenidos a este post en el cual voy a estar explicando los conceptos básicos de Buffer Overflow.

## ¿Qué es un buffer?

Para entender que es el desbordamiento del búfer, primero debemos saber que es un búfer.

Un búfer es un espacio de memoria, en el que se almacenan datos de manera temporal, los cuales un programa está procesando o simplemente está preparándose para procesar, estos datos pueden ser:

- Cadena de caracteres
- Archivos de texto
- Imágenes
- Audios

Esa memoria tiene cierto tamaño asignado, supongamos que tenemos un campo en el cual debemos proporcionar nuestro nombre, ese campo tiene un buffer asignado de 6 bytes. 

<img src="buffer-imagen.png">

Como vemos en la imagen, tenemos un buffer asignado de 6 bytes, en el cual se almacena nuestro nombre, pero...

¿Qué pasa si ponemos un nombre que sobrepase esos 6 bytes?

Bueno, aquí es donde ocurre el buffer overflow, cuando pasamos más datos de los cuales está esperando el programa, esto puede generar que el programa deje de funcionar o que nosotros nos aprovechemos de ese error para que el programa ejecute nuestras instrucciones maliciosas.

Pero antes de esto, debemos saber qué pasa por detrás cuando nosotros ejecutamos un programa en la memoria.

# ¿Qué pasa al ejecutar un programa?

Como les dije anteriormente, debemos saber qué pasa por detrás cuando ejecutamos un programa.


<img src="proceso-en-memoria.png">

Como vemos, al ejecutar un programa en memoria, esta se divide en 4 segmentos.

- Text: Este segmento de la memoria se utiliza para almacenar el código ejecutable del programa, es decir, se almacena el código fuente del programa.

- Datos: 
  
  - Data Inicializada: Los datos inicializados son aquellos que tienen un valor asignado en el momento de la compilación.

  - Data no Inicializada: los datos no inicializados son aquellos que no tienen un valor asignado en el momento de la compilación. Estos datos se almacenan en la sección de bss (Block Started by Symbol) del ejecutable (El BSS es una sección de memoria utilizada para almacenar variables globales y estáticas que no tienen un valor inicial específico.)

- Heap: El Heap es una estructura de datos dinámica en la memoria que se utiliza para almacenar objetos y datos que pueden ir cambiando al momento de ejecutar el programa.

- Stack: El Stack es una estructura de datos LIFO (Last In First Out) utilizada para almacenar información sobre las funciones, variables locales y otros datos temporales, usemos como ejemplo el búfer o variable nombre del inicio, bueno, esa variable se almacena dentro del stack.


No podemos terminar este post así, voy a explicarles detalladamente que es el Stack, ya que de eso se trata el post, de ```Stack buffer overflow``` jaja.

# ¿Qué es el Stack?

Bueno, como les comente en el apartado de arriba, el Stack tiene una estructura de datos LIFO

## ¿Qué es una estructura LIFO?

LIFO es un acrónimo que significa Last-In, First-Out, que en español significa Último en Entrar, Primero en Salir. Es un tipo de estructura de datos en la que el último elemento que se agregó a la estructura es el primero en ser retirado.

## Áreas del Stack
Bueno, al igual que la memoria se divide en partes al ejecutar un programa, el stack también lo hace.

<img src="areas-stack.png">

- Dirección de retorno: La dirección de retorno es una dirección en el código que se almacena en el stack cada vez que se llama a una función. Esta dirección indica dónde debe continuar la ejecución después de que se ha completado la función. La dirección de retorno necesaria para que el programa se ejecute de forma correcta.

- Parámetros: Los parámetros en el stack es una área que almacena los valores que le pasamos a una función, es decir, al momento de que una función se ejecute en el programa, los parámetros que nosotros le indicamos son llevados al stack, estos se extraen cuando la función ha terminado de ejecutarse.

- Variables Locales: Las variables locales son aquellas variables que se definen dentro de una función  y sólo están disponibles dentro de esa función.

- Registros: Los registros son áreas de memoria especiales dentro del procesador que se utilizan para almacenar información temporal y para optimizar el rendimiento del procesador.

EHH! que no se me olvide explicar que es el procesador o CPU, ya que gracias a este componente podemos ejecutar los programas.

## ¿Qué es el CPU?

El componente de la computadora responsable de ejecutar los programas es el procesador (CPU). El procesador es el "cerebro" de la computadora y es el que se encarga de interpretar y ejecutar las instrucciones que se le dan a la computadora.

# ¿Qué es el ESP?

El ESP (Stack Pointer) es un registro en el CPU que se utiliza para mantener la dirección de la parte superior del stack durante la ejecución de un programa. El ESP apunta siempre a la última posición y cada vez que se modifica un elemento del stack, el valor del ESP se actualiza para reflejar la nueva posición de la parte superior del stack.

Las direcciones de memoria se ven como números hexadecimales, los cuales representan la posición de un byte en la memoria. Por ejemplo, la dirección 0x625011AF representa una posición en la memoria.

# Explicación con programa.

Para poder comprender de mejor manera la explicación del Stack Buffer Overflow, vamos a estar practicando con un simple programa hecho en C.

```c
#include <stdio.h>
#include <string.h>

void func(char *str) {
  char buffer[8];
  strcpy(buffer, str);
}

int main(int argc, char *argv[]) {
  printf("Programa para comprender el Stack Buffer Overflow\n");

  if (argc < 2) {
    printf("\nUso: %s <caracteres>\n", argv[0]);
    return 1;
  }
  
  int len = strlen(argv[1]);
  printf("Caracteres ingresados: %d\n", len);

  func(argv[1]);
  return 0;
}
```

Este programa define una función llamada "func" que toma una cadena de caracteres como argumento y la copia en un buffer de 8 bytes.

Para compilar este programa vamos a usar el siguiente comando.

```gcc -o vulnerable vulnerable.c```

Bien, una vez que tengamos el programa, al ejecutarlo nos pedirá le pasemos caracteres como argumento.

```
❯ ./vulnerable
Programa para comprender el Stack Buffer Overflow

Uso: ./vulnerable <caracteres>

❯ ./vulnerable test
Programa para comprender el Stack Buffer Overflow
Caracteres ingresados: 4
```

Como vemos, al ejecutarlo y pasarle como argumento la palabra "test", no devuelve que es una palabra de 4 caracteres.

Si recordamos, el código puede almacenar palabras que sean menor a 8 caracteres, ya que ese es el buffer que le asignamos, es decir, el tamaño que le definimos.

Pero...

¿Y si le pasamos una palabra que sobrepase los 8 caracteres? Como por ejemplo, la palabra "Australia" o "Argentina".

```
❯ ./vulnerable Argentina
Programa para comprender el Stack Buffer Overflow
Caracteres ingresados: 9
Violación de segmento
```

Como vemos, al pasarle una palabra que contenga más de 8 caracteres, nuestro sistema nos devuelve el mensaje "Violación de segmento"

¿Por qué pasa esto?

Esto pasa porque le pasamos más bytes de los que el programa estaba esperando, y esto genera que apunte a un dirección de memoria inexistente, es decir, que intenta acceder a una dirección de memoria que no le pertenece, y como medida de seguridad nuestro sistema envía una señal al proceso del programa para que termine la ejecución del mismo

Para ya ir terminando con este post de conceptos básicos de buffer overflow, explicaré que son las direcciones en little endian y big endian.

# ¿Qué es el formato Little Endian?

Las direcciones en Little-Endian son una forma por así decirlo de almacenar datos en la memoria, en la cual los bytes menos significativos se almacenan en una dirección de memoria más baja, y los bytes más significativos se almacenan en una dirección de memoria más alta. igualmente, estas formas de almacenamiento se suelen usar en procesadores de arquitectura x86, las direcciones en Little Endian se pueden considerar como direcciones "dadas vuelta"

Supongamos que tenemos esta dirección de memoria: 
- ```0x625011AF```

Bueno, en Little Endian se representa asi: 

- ```AF115062```

# ¿Qué es el formato Big Endian?

El formato Big-Endian es lo mismo que el Little Endian, solamente que al revés, es decir, que el byte menos significativo se almacenan en las direcciones de memoria más altas y los bytes más significativos se almacenan en las direcciones de memoria más bajas, esta forma de almacenamiento suele ser mas utilizadas en sistemas operativos basados en UNIX.

Normalmente de la forma que se visualizan las direcciones en Big Endian son con los bytes más significativos a la izquierda y los bytes menos significativos a la derecha.

# Despedida

Bueno, llegamos al final de este post en el cual espero haberte podido ayudar a comprender los conceptos básicos que hay que saber antes de explotar un Stack Buffer Overflow, próximamente estaré subiendo otros posts en los cuales enseñaré paso a paso como poder llevar a cabo una explotación de buffer overflow con éxito.

Materiales de refuerzo:

- https://deephacking.tech/fundamentos-para-buffer-overflow/
- https://keepcoding.io/blog/que-es-un-buffer-overflow/
- https://youtu.be/7KZ5LCFr6Sw

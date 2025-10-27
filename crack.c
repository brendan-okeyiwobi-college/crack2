#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *digest = md5(plaintext, (int)strlen(plaintext));
    if (digest == NULL) {
        fprintf(stderr, "md5() returned NULL\n");
        return NULL;
    }

    // Open the hash file
    FILE *hf = fopen(hashFilename, "r");
    if (hf == NULL) {
        perror("Error opening hash file");
        free(digest);
        return NULL;
    }

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN + 8];
    while (fgets(line, sizeof(line), hf)) {
        // strip newline and CR if present
        line[strcspn(line, "\r\n")] = '\0';

        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(line, digest) == 0) {
            // If there is a match, you'll return the hash.
            // duplicate the matched hash so caller can use/free it
            char *found = strdup(line);

            // Before returning, do any needed cleanup:
            //   Close files?
            //   Free memory?
            free(digest);
            fclose(hf);

            // Return the matched hash (caller is responsible for free())
            return found;
        }
    }

    // If not found, return NULL.
    free(digest);
    fclose(hf);
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.
    // (We implement full behavior below, so these test lines are omitted.)

    // Open the dictionary file for reading.
    FILE *df = fopen(argv[2], "r");
    if (df == NULL) {
        perror("Error opening dictionary file");
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    char word[PASS_LEN + 4];
    int cracked = 0;
    while (fgets(word, sizeof(word), df)) {
        // strip newline/CR
        word[strcspn(word, "\r\n")] = '\0';
        if (word[0] == '\0') continue; // skip empty lines

        // call tryWord with this candidate
        char *foundHash = tryWord(word, argv[1]);

        // If we got a match, display the hash and the word. For example:
        //   5d41402abc4b2a76b9719d911017c592 hello
        if (foundHash != NULL) {
            printf("%s %s\n", foundHash, word);
            free(foundHash);
            cracked++;
        }
    }

    // Close the dictionary file.
    fclose(df);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked!\n", cracked);

    // Free up any malloc'd memory? (All malloc'd memory in this program is freed.)
    return 0;
}
#include <sodium.h>
#include<string.h>
#include <time.h>
struct block{
unsigned char *vpublic_key;
unsigned char *vproof;
unsigned char *bpublic_key;
unsigned char *bproof;
}*head;
struct block *block2;
struct block *block3;
struct block *block4;
struct block *block5;
unsigned char* toString(struct block b)
{
  unsigned char *str=malloc(sizeof(unsigned char)*sizeof(b));
  memcpy(str,&b,sizeof(b));
  return str;
}
// Generate a NIZK proof
void generate_nizk_proof(unsigned char *secret_data, unsigned char *public_key, unsigned char *proof, unsigned char *secret_key) {
  // Generate a commitment
  
  unsigned char commitment[crypto_core_ed25519_BYTES];
  unsigned char hashed_secret_data[crypto_generichash_blake2b_BYTES];
  crypto_generichash_blake2b(hashed_secret_data, sizeof(hashed_secret_data), secret_data, sizeof(secret_data), NULL, 0);
  crypto_core_ed25519_add(commitment, hashed_secret_data, public_key);

  // Generate a challenge
  unsigned char challenge[crypto_generichash_blake2b_BYTES];
  randombytes_buf(challenge, sizeof(challenge));

  // Generate a response
  unsigned char response[crypto_core_ed25519_SCALARBYTES];
  crypto_scalarmult_ed25519_base(response, challenge);
  crypto_core_ed25519_scalar_add(response, response, secret_key);

  // Copy the proof to the output buffer
  memcpy(proof, commitment, sizeof(commitment));
  memcpy(proof + sizeof(commitment), response, sizeof(response));
}

// Verify a NIZK proof
int verify_nizk_proof(unsigned char *public_key, unsigned char *proof) {
  // Extract the commitment and response from the proof buffer
  unsigned char commitment[crypto_core_ed25519_BYTES];
  unsigned char response[crypto_core_ed25519_SCALARBYTES];
  memcpy(commitment, proof, sizeof(commitment));
  memcpy(response, proof + sizeof(commitment), sizeof(response));

  // Recompute the commitment
  unsigned char recomputed_commitment[crypto_core_ed25519_BYTES];
  crypto_scalarmult_ed25519_base(recomputed_commitment, response);

  // Verify that the commitments match
  if (crypto_verify_32(commitment, recomputed_commitment) == 0) {
    return 0; // Proof verification failed
  } else {
    return 1; // Proof verification successful
  }
}

// Example usage:

int main() {
  // Generate an Edwards key pair
  printf("Generate proof for first block");
  unsigned char public_key[crypto_scalarmult_ed25519_BYTES];
  unsigned char secret_key[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(secret_key, sizeof(secret_key));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(public_key, secret_key);
unsigned char bpublic_key[crypto_scalarmult_ed25519_BYTES];
  unsigned char bsecret_key[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(bsecret_key, sizeof(bsecret_key));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(bpublic_key, bsecret_key);

  // Generate a secret data to prove
   unsigned char *filename1=(unsigned char *)malloc(17);
  
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename1);
 clock_t tic = clock();
FILE *file = fopen(filename1, "rb");
if (file == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize = 0;
    
    fseek(file, 0, SEEK_END);
   fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
 unsigned char *fileContents = (unsigned char*) malloc(sizeof(char) * fileSize);
   size_t amountRead = fread(fileContents, fileSize, 1, file);

  /*unsigned char secret_data[32];
  randombytes_buf(secret_data, sizeof(secret_data));*/

  // Generate a NIZK proof

  unsigned char proof[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(fileContents, public_key, proof, secret_key);
  head=malloc(sizeof(struct block));
  head->vpublic_key=public_key;
  head->vproof=proof;
unsigned char bproof[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof("", bpublic_key, bproof, bsecret_key);
  head->bpublic_key=bpublic_key;
  head->bproof=bproof;
clock_t toc = clock();

  
    
printf("Elapsed: %f seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC);

printf("Generate proof for second block");
  unsigned char public_key2[crypto_scalarmult_ed25519_BYTES];
  unsigned char secret_key2[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(secret_key2, sizeof(secret_key2));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(public_key2, secret_key2);
unsigned char bpublic_key2[crypto_scalarmult_ed25519_BYTES];
  unsigned char bsecret_key2[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(bsecret_key2, sizeof(bsecret_key2));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(bpublic_key2, bsecret_key2);

  // Generate a secret data to prove
   unsigned char *filename2=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename2);
clock_t tic01 = clock();
FILE *file2 = fopen(filename2, "rb");
if (file2 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize2 = 0;
    
    fseek(file2, 0, SEEK_END);
   fileSize2 = ftell(file2);
    fseek(file2, 0, SEEK_SET);
 unsigned char *fileContents2 = (unsigned char*) malloc(sizeof(char) * fileSize2);
   size_t amountRead2 = fread(fileContents2, fileSize2, 1, file2);

  /*unsigned char secret_data[32];
  randombytes_buf(secret_data, sizeof(secret_data));*/

  // Generate a NIZK proof
  unsigned char proof2[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(fileContents2, public_key2, proof2, secret_key2);
  block2=malloc(sizeof(struct block));
  block2->vpublic_key=public_key2;
  block2->vproof=proof2;
unsigned char bproof2[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(toString(*head), bpublic_key2, bproof2, bsecret_key2);
 block2->bpublic_key=bpublic_key2;
  block2->bproof=bproof2;
clock_t toc01 = clock();    
printf("Elapsed: %f seconds\n", (double)(toc01 - tic01) / CLOCKS_PER_SEC);

printf("Generate proof for third block");
  unsigned char public_key3[crypto_scalarmult_ed25519_BYTES];
  unsigned char secret_key3[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(secret_key3, sizeof(secret_key3));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(public_key3, secret_key3);
unsigned char bpublic_key3[crypto_scalarmult_ed25519_BYTES];
  unsigned char bsecret_key3[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(bsecret_key3, sizeof(bsecret_key3));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(bpublic_key3, bsecret_key3);

  // Generate a secret data to prove
   unsigned char *filename3=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename3);
 clock_t tic02 = clock();
FILE *file3 = fopen(filename3, "rb");
if (file3 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize3 = 0;
    
    fseek(file3, 0, SEEK_END);
   fileSize3 = ftell(file3);
    fseek(file3, 0, SEEK_SET);
 unsigned char *fileContents3 = (unsigned char*) malloc(sizeof(char) * fileSize3);
   size_t amountRead3 = fread(fileContents3, fileSize3, 1, file3);

  /*unsigned char secret_data[32];
  randombytes_buf(secret_data, sizeof(secret_data));*/

  // Generate a NIZK proof
  unsigned char proof3[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(fileContents3, public_key3, proof3, secret_key3);
  block3=malloc(sizeof(struct block));
  block3->vpublic_key=public_key3;
  block3->vproof=proof3;
unsigned char bproof3[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(toString(*block2), bpublic_key3, bproof3, bsecret_key3);
 block3->bpublic_key=bpublic_key3;
  block3->bproof=bproof3;
clock_t toc02 = clock();    
printf("Elapsed: %f seconds\n", (double)(toc02 - tic02) / CLOCKS_PER_SEC);

printf("Generate proof for fourth block");
  unsigned char public_key4[crypto_scalarmult_ed25519_BYTES];
  unsigned char secret_key4[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(secret_key4, sizeof(secret_key4));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(public_key4, secret_key4);
unsigned char bpublic_key4[crypto_scalarmult_ed25519_BYTES];
  unsigned char bsecret_key4[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(bsecret_key4, sizeof(bsecret_key4));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(bpublic_key4, bsecret_key4);

  // Generate a secret data to prove
   unsigned char *filename4=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename4);
clock_t tic03 = clock();
FILE *file4 = fopen(filename4, "rb");
if (file4 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize4 = 0;
    
    fseek(file4, 0, SEEK_END);
   fileSize4 = ftell(file4);
    fseek(file4, 0, SEEK_SET);
 unsigned char *fileContents4 = (unsigned char*) malloc(sizeof(char) * fileSize4);
   size_t amountRead4 = fread(fileContents4, fileSize4, 1, file4);

  /*unsigned char secret_data[32];
  randombytes_buf(secret_data, sizeof(secret_data));*/

  // Generate a NIZK proof
  unsigned char proof4[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(fileContents4, public_key4, proof4, secret_key4);
  block4=malloc(sizeof(struct block));
  block4->vpublic_key=public_key4;
  block4->vproof=proof4;
unsigned char bproof4[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(toString(*block3), bpublic_key4, bproof4, bsecret_key4);
 block4->bpublic_key=bpublic_key4;
  block4->bproof=bproof4;

clock_t toc03 = clock();    
printf("Elapsed: %f seconds\n", (double)(toc03 - tic03) / CLOCKS_PER_SEC);

printf("Generate proof for fifth block");
  unsigned char public_key5[crypto_scalarmult_ed25519_BYTES];
  unsigned char secret_key5[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(secret_key5, sizeof(secret_key5));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(public_key5, secret_key5);
unsigned char bpublic_key5[crypto_scalarmult_ed25519_BYTES];
  unsigned char bsecret_key5[crypto_scalarmult_ed25519_SCALARBYTES];

  // Generate a random secret key
  randombytes_buf(bsecret_key5, sizeof(bsecret_key5));

  // Compute the public key from the secret key
  crypto_scalarmult_ed25519_base(bpublic_key5, bsecret_key5);

  // Generate a secret data to prove
   unsigned char *filename5=(unsigned char *)malloc(17);
printf("\n\nPlease Enter the video name: \n");
scanf("%s",filename5);
clock_t tic04 = clock();
FILE *file5 = fopen(filename5, "rb");
if (file5 == NULL)
    {
        printf("Error: Invalid file.\n");
    }
    
    long int fileSize5 = 0;
    
    fseek(file5, 0, SEEK_END);
   fileSize5 = ftell(file5);
    fseek(file5, 0, SEEK_SET);
 unsigned char *fileContents5 = (unsigned char*) malloc(sizeof(char) * fileSize5);
   size_t amountRead5 = fread(fileContents5, fileSize5, 1, file5);

  /*unsigned char secret_data[32];
  randombytes_buf(secret_data, sizeof(secret_data));*/

  // Generate a NIZK proof
  unsigned char proof5[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(fileContents5, public_key5, proof5, secret_key5);
  block5=malloc(sizeof(struct block));
  block5->vpublic_key=public_key5;
  block5->vproof=proof5;
unsigned char bproof5[crypto_core_ed25519_BYTES + crypto_core_ed25519_SCALARBYTES];
  generate_nizk_proof(toString(*block4), bpublic_key5, bproof5, bsecret_key5);
 block5->bpublic_key=bpublic_key5;
  block5->bproof=bproof5;
clock_t toc04 = clock();    
printf("Elapsed: %f seconds\n", (double)(toc04 - tic04) / CLOCKS_PER_SEC);

  printf("verification of first block\n");
  clock_t tic1 = clock();
  // Verify the NIZK proof
  int is_valid_proof = verify_nizk_proof(head->vpublic_key, head->vproof);

  if (is_valid_proof) {
    printf("VProof verified successfully!\n");
  } else {
    printf("VProof verification failed!\n");
  }
  int is_valid_proofb = verify_nizk_proof(head->bpublic_key, head->bproof);

  if (is_valid_proofb) {
    printf("BProof verified successfully!\n");
  } else {
    printf("BProof verification failed!\n");
  }
  clock_t toc1 = clock();
printf("Elapsed: %f seconds\n", (double)(toc1 - tic1) / CLOCKS_PER_SEC);

  printf("verification of second block\n");
  clock_t tic2 = clock();
  // Verify the NIZK proof
  int is_valid_proof2 = verify_nizk_proof(block2->vpublic_key, block2->vproof);

  if (is_valid_proof2) {
    printf("VProof verified successfully!\n");
  } else {
    printf("VProof verification failed!\n");
  }
  int is_valid_proofb2 = verify_nizk_proof(block2->bpublic_key, block2->bproof);

  if (is_valid_proofb2) {
    printf("BProof verified successfully!\n");
  } else {
    printf("BProof verification failed!\n");
  }
  clock_t toc2 = clock();
printf("Elapsed: %f seconds\n", (double)(toc2 - tic2) / CLOCKS_PER_SEC);

  printf("verification of third block\n");
  clock_t tic3 = clock();
  // Verify the NIZK proof
  int is_valid_proof3 = verify_nizk_proof(block3->vpublic_key, block3->vproof);

  if (is_valid_proof3) {
    printf("VProof verified successfully!\n");
  } else {
    printf("VProof verification failed!\n");
  }
  int is_valid_proofb3 = verify_nizk_proof(block3->bpublic_key, block3->bproof);

  if (is_valid_proofb3) {
    printf("BProof verified successfully!\n");
  } else {
    printf("BProof verification failed!\n");
  }
  clock_t toc3 = clock();

  
    
printf("Elapsed: %f seconds\n", (double)(toc3 - tic3) / CLOCKS_PER_SEC);

  printf("verification of fourth block\n");
  // Verify the NIZK proof
  clock_t tic4 = clock();
  int is_valid_proof4 = verify_nizk_proof(block4->vpublic_key, block4->vproof);

  if (is_valid_proof4) {
    printf("VProof verified successfully!\n");
  } else {
    printf("VProof verification failed!\n");
  }
  int is_valid_proofb4 = verify_nizk_proof(block4->bpublic_key, block4->bproof);

  if (is_valid_proofb4) {
    printf("BProof verified successfully!\n");
  } else {
    printf("BProof verification failed!\n");
  }
  clock_t toc4 = clock();

  
    
printf("Elapsed: %f seconds\n", (double)(toc4 - tic4) / CLOCKS_PER_SEC);

  printf("Verification of fifith block\n");
  clock_t tic5 = clock();
  // Verify the NIZK proof
  int is_valid_proof5 = verify_nizk_proof(block5->vpublic_key, block5->vproof);

  if (is_valid_proof5) {
    printf("VProof verified successfully!\n");
  } else {
    printf("VProof verification failed!\n");
  }
  int is_valid_proofb5 = verify_nizk_proof(block2->bpublic_key, block2->bproof);

  if (is_valid_proofb5) {
    printf("BProof verified successfully!\n");
  } else {
    printf("BProof verification failed!\n");
  }
  clock_t toc5 = clock();

  
    
printf("Elapsed: %f seconds\n", (double)(toc5 - tic5) / CLOCKS_PER_SEC);


  return 0;
}


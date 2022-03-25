#include <iostream>
#define ROUND_COUNT 32

unsigned char plain_text[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};//Тестовый открытый текст
unsigned char key_80bit[10] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };//Тестовый 80-битный секретный ключ
unsigned char key_128bit[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };//Тестовый 128-битный секретный ключ

unsigned char S_layer[16] = {0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2};//S-блок

unsigned char S_reverse_layer[16] = { 0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa };//S-1-блок

unsigned char P_layer[64] = {0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20,
36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10,
26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61,14, 30, 46, 62, 15, 31, 47, 63};//P-блок

unsigned char P_reverse_layer[64] = { 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42,
46, 50, 54, 58, 62, 3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63};//P-1-блок

uint64_t keys[32];//Массив раундовых ключей

//Функция реализующая расписание выработки раундовых ключей из секретного 80-битного ключа
void key_shedule_80bit(uint8_t *key) {
    uint8_t round_counter = 1;//Переменная, хранящая номер раунда при выработке раундового ключа
    uint64_t key_left_side = 0;//Левая часть ключа (64 бита)
    uint16_t key_right_side = 0;//Правая часть ключа (16 бит)
    uint64_t temp_left = 0;
    uint16_t temp_right = 0;
    //получаем биты левой части ключа
    for (int i = 0; i < 8; i++) {
        temp_left = key[i];
        key_left_side = key_left_side << 8;
        key_left_side ^= temp_left;
    }
    //получаем биты правой части ключа
    for(int i = 8; i < 10; i++){
        temp_right = key[i];
        key_right_side = key_right_side << 8;
        key_right_side ^= temp_right;
    }
    //Осуществляем преобразование 32 раундового ключа
    for (int j = 0; j < ROUND_COUNT; j++) {
        //Берём левые 64 бита для получения раундового ключа
        keys[j] = key_left_side;
        //Выполняем перестановку на 61 бит влево
        for (int i = 0; i < 61; i++) {
            uint8_t first_bit_left_side = (key_left_side >> 63) & 1;
            uint8_t first_bit_right_side = (key_right_side >> 15) & 1;
            key_left_side = key_left_side << 1;
            key_left_side ^= first_bit_right_side;
            key_right_side = key_right_side << 1;
            key_right_side ^= first_bit_left_side;
        }
        //Пропускаем 4 последних бита ключа через S блок
        uint64_t key_to_s_layer = S_layer[
            ((key_left_side >> 63) & 1) << 3 |
                ((key_left_side >> 62) & 1) << 2 |
                ((key_left_side >> 61) & 1) << 1 |
                (key_left_side >> 60) & 1
        ];
        //Заменяем 4 последних бита полученными значениями
        key_to_s_layer = key_to_s_layer << 60;
        key_left_side = (key_left_side & 0x0fffffffffffffff) ^ key_to_s_layer;
        //Достаём биты с 15 по 19 и суммируем по модулю 2 с номером раунда round_counter
        uint16_t key_bits = (((key_left_side >> 3) & 1) << 4) |
            (((key_left_side >> 2) & 1) << 3) |
            (((key_left_side >> 1) & 1) << 2) |
            ((key_left_side & 1) << 1) |
            ((key_right_side >> 15) & 1);
        key_bits ^= round_counter;
        //Заменяем значения битов с 15 по 19 ранее полученными
        key_left_side = key_left_side & 0xfffffffffffffff0;
        key_right_side = key_right_side & 0x7fff;
        key_right_side ^= (key_bits & 1) << 15;
        key_left_side ^= key_bits >> 1;
        //Инкрементируем счётчик раундов
        round_counter += 1;
    }
}

//Функция реализующая расписание выработки раундовых ключей из секретного 128-битного ключа
void key_shedule_128bit(uint8_t *key) {
    uint8_t round_counter = 1;//Переменная, хранящая номер раунда при выработке раундового ключа
    uint64_t key_left_side = 0;//Левая часть ключа (64 бита)
    uint64_t key_right_side = 0;//Правая часть ключа (16 бит)
    uint64_t temp = 0;
    //получаем биты левой части ключа
    for (int i = 0; i < 8; i++) {
        temp = key[i];
        key_left_side = key_left_side << 8;
        key_left_side ^= temp;
    }
    //получаем биты правой части ключа
    for (int i = 8; i < 16; i++) {
        temp = key[i];
        key_right_side = key_right_side << 8;
        key_right_side ^= temp;
    }
    for (int j = 0; j < ROUND_COUNT; j++) {
        //Берём левые 64 бита для получения раундового ключа
        keys[j] = key_left_side;
        //Выполняем перестановку на 61 бит влево
        for (int i = 0; i < 61; i++) {
            uint8_t first_bit_left_side = (key_left_side >> 63) & 1;
            uint8_t first_bit_right_side = (key_right_side >> 63) & 1;
            key_left_side = key_left_side << 1;
            key_left_side ^= first_bit_right_side;
            key_right_side = key_right_side << 1;
            key_right_side ^= first_bit_left_side;
        }
        //Пропускаем 125-128 биты ключа через S блок
        uint64_t key_to_s_layer = S_layer[
            ((key_left_side >> 63) & 1) << 3 |
                ((key_left_side >> 62) & 1) << 2 |
                ((key_left_side >> 61) & 1) << 1 |
                (key_left_side >> 60) & 1
        ];
        key_to_s_layer = key_to_s_layer << 4;
        //Пропускаем 121-124 биты ключа через S блок
        key_to_s_layer ^= S_layer[
            ((key_left_side >> 59) & 1) << 3 |
                ((key_left_side >> 58) & 1) << 2 |
                ((key_left_side >> 57) & 1) << 1 |
                (key_left_side >> 56) & 1
        ];
        key_to_s_layer = key_to_s_layer << 56;
        key_left_side = (key_left_side & 0x00ffffffffffffff) ^ key_to_s_layer;
        //Достаём биты с 62 по 66 и суммируем по модулю 2 с номером раунда round_counter
        uint64_t key_bits = (((key_left_side >> 2) & 1) << 4) |
            (((key_left_side >> 1) & 1) << 3) |
            ((key_left_side & 1) << 2) |
            ((key_right_side >> 63 & 1) << 1) |
            ((key_right_side >> 62) & 1);
        key_bits ^= round_counter;
        //Заменяем значения битов с 62 по 66 ранее полученными
        key_left_side = key_left_side & 0xfffffffffffffff8;
        key_right_side = key_right_side & 0x3fffffffffffffff;
        key_right_side ^= ((key_bits & 1) << 62) ^ (((key_bits >> 1) & 1) << 63);
        key_left_side ^= key_bits >> 2;
        //Инкрементируем счётчик раундов
        round_counter += 1;
    }
}

//Функция, реализующая нелинейное обратное преобразование
uint64_t S_reverse_block(uint64_t input_block) {
    uint64_t S_output = 0;
    for (int i = 63; i >= 3; i-=4) {
        S_output = S_output << 4;
        S_output ^= S_reverse_layer[
            (((input_block >> (i-3)) & 1)) |
            (((input_block >> (i-2)) & 1) << 1) |
            (((input_block >> (i-1)) & 1) << 2) |
            (((input_block >> i) & 1) << 3)
        ];
    }
    return S_output;
}

//Функция, реализующая перестановку бит P-1
uint64_t P_reverse_block(uint64_t input_block) {
    uint64_t P_output = 0;
    for (int i = 63; i >= 0; i--) {
        P_output ^= ((input_block >> i) & 1) << P_reverse_layer[i];
    }
    return P_output;
}

//Функция, реализующая нелинейное преобразование
uint64_t S_block(uint64_t input_block) {
    uint64_t S_output = 0;
    for (int i = 63; i >= 3; i -= 4) {
        S_output = S_output << 4;
        S_output ^= S_layer[
            (((input_block >> (i - 3)) & 1)) |
                (((input_block >> (i - 2)) & 1) << 1) |
                (((input_block >> (i - 1)) & 1) << 2) |
                (((input_block >> i) & 1) << 3)
        ];
    }
    return S_output;
}

//Функция, реализующая перестановку бит
uint64_t P_block(uint64_t input_block) {
    uint64_t P_output = 0;
    for (int i = 63; i >= 0; i--) {
        P_output ^= ((input_block >> i) & 1) << P_layer[i];
    }
    return P_output;
}

//Функция шифрования открытого текста
void encrypt(uint8_t* plaintext) {
    uint64_t input_text = 0;
    uint64_t temp_text = 0;
    for (int i = 0; i < 8; i++) {
        temp_text = plaintext[i];
        input_text = input_text << 8;
        input_text ^= temp_text;
    }
    //32 раунда шифра
    for (int i = 0; i < ROUND_COUNT-1; i++) {
        input_text ^= keys[i];// Операция xor выхода предыдущего блока с раундовым ключём
        input_text = S_block(input_text);//Нелинейное преобразование
        input_text = P_block(input_text);//Перестановка бит
    }
    input_text ^= keys[31];//Отбеливание ключа
    //Заполнение массива
    for (int i = 63, j = 0; i >= 7; i -= 8, j++) {
        plain_text[j] = ((input_text >> (i - 7)) & 1) |
            (((input_text >> (i - 6)) & 1) << 1) |
            (((input_text >> (i - 5)) & 1) << 2) |
            (((input_text >> (i - 4)) & 1) << 3) |
            (((input_text >> (i - 3)) & 1) << 4) |
            (((input_text >> (i - 2)) & 1) << 5) |
            (((input_text >> (i - 1)) & 1) << 6) |
            (((input_text >> i) & 1) << 7);
    }
}

//Функция расшифрования открытого текста
void decrypt(uint8_t* ciphertext) {
    uint64_t input_text = 0;
    uint64_t temp_text = 0;
    for (int i = 0; i < 8; i++) {
        temp_text = ciphertext[i];
        input_text = input_text << 8;
        input_text ^= temp_text;
    }
    //Выполняем действия шифра в обратном порядке
    input_text ^= keys[31];
    //32 раунда шифра
    for (int i = ROUND_COUNT - 2; i >= 0; i--) {
        input_text = P_reverse_block(input_text);//Обратная перестановка бит
        input_text = S_reverse_block(input_text);//Обратное нелинейное преобразование
        input_text ^= keys[i];// Операция xor раундовым ключём
    }
    //Заполнение массива
    for (int i = 63, j = 0; i >= 7; i -= 8, j++) {
        ciphertext[j] = ((input_text >> (i - 7)) & 1) |
            (((input_text >> (i - 6)) & 1) << 1) |
            (((input_text >> (i - 5)) & 1) << 2) |
            (((input_text >> (i - 4)) & 1) << 3) |
            (((input_text >> (i - 3)) & 1) << 4) |
            (((input_text >> (i - 2)) & 1) << 5) |
            (((input_text >> (i - 1)) & 1) << 6) |
            (((input_text >> i) & 1) << 7);
    }
}

int main()
{
    key_shedule_80bit(key_80bit);//Запускаем выработку 80-битного ключа
    printf("Encrypting with 80-bit key\nInput text:\n");
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
    printf("\nEncrypted text:\n");
    encrypt(plain_text);//Шифруем текст
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
    printf("\nText was decrypted again:\n");
    decrypt(plain_text);//Расшифровываем текст
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
    key_shedule_128bit(key_128bit);//Запускаем выработку 128-битного ключа
    printf("\n\nEncrypting with 128-bit key\nInput text:\n");
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
    printf("\nEncrypted text:\n");
    encrypt(plain_text);//Шифруем текст
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
    printf("\nText was decrypted again:\n");
    decrypt(plain_text);//Расшифровываем текст
    for (int i = 0; i < 8; i++) {
        printf("%x ", plain_text[i]);
    }
}

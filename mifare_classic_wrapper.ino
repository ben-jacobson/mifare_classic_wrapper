/*
 * 
 * 
 *   Todo:
 *    - remove the dependancy on MAX_SERIAL_READ within the class. Replace with something where you can read/write an entire block
 *    - change some of these functions to return a status code on error
 */

#include <SPI.h>  // Ardino SPI bus library
#include <MFRC522.h> // RFID-RC522 Library - Download from here - https://github.com/miguelbalboa/rfid and click "add to library" to run this example

#define MAX_BLOCK_SIZE 16 // you can store 16 characters into any RFID block
#define READ_BUFFER_SIZE 18

/*
 * 
 *  Classes and helper functions
 * 
 */

void dump_byte_array_to_serial(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " "); // Found a pretty clever way of padding 0's and adding spaces in the Mifare library, so I pinched this for my own use. 
        Serial.print(buffer[i], HEX);
    }
    Serial.println();
}
 
class mifare_classic_wrapper {
    /*
     *  Wrapper for the RFID-RC522 library - 
     *  Dependancies:
     *    - #include <SPI.h>  // Default library for SPI bus interaction
     *    - #include <MFRC522.h> // RFID-RC522 Library - Download from here - https://github.com/miguelbalboa/rfid and click "add to library" to run this example
     *    - #define MAX_BLOCK_SIZE 32 // we also have a const stored in the class, but is needed for some function arguments
     *    - #define READ_BUFFER_SIZE 18
     *    - Must have SPI.begin and Serial.begin run before running the initialize function.      
     */
    private:
        MFRC522 rfid_scanner;
        MFRC522::MIFARE_Key key;
        MFRC522::PICC_Type piccType;
        String piccTypeName;

        byte read_buffer[READ_BUFFER_SIZE];
        
        const byte CRYPTO_KEY_LENGTH = 6; 
        byte reader_version;

        void prepare_default_crypto_key(void) {
            // Prepare a blank crypto key (used both as key A and as key B) for the encryption needed for writing. Factory default for most cards = FFFFFFFFFFFFh
            for (byte i = 0; i < this->CRYPTO_KEY_LENGTH; i++) {
                this->key.keyByte[i] = 0xFF;
            }            
        }
              
    public:    
        mifare_classic_wrapper() {
            // do nothing for now,
            // run Serial.begin() and SPI.begin() in the init() method, then run the initialize function after that. 
        }
        
        void initialize(byte ss_pin, byte reset_pin) {                        
            this->rfid_scanner.PCD_Init(ss_pin, reset_pin);  // init the scanner                 
            this->prepare_default_crypto_key(); 
            this->get_reader_version();
        }
     
        byte get_reader_version(void) {
            // Gets the MFRC522 software version
            this->reader_version = this->rfid_scanner.PCD_ReadRegister(this->rfid_scanner.VersionReg);
        }        

        void get_picc_type(void) {
            this->piccType = this->rfid_scanner.PICC_GetType(this->rfid_scanner.uid.sak);  
            this->piccTypeName = this->rfid_scanner.PICC_GetTypeName(this->piccType);
        }

        bool authenticate_key_a(byte trailerBlock) {
            MFRC522::StatusCode attempt_auth;
          
            // Authenticate using key A
            Serial.print("Attempting to authenticate using key A... ");            
            attempt_auth = (MFRC522::StatusCode) this->rfid_scanner.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &this->key, &(this->rfid_scanner.uid));
            
            if (attempt_auth != MFRC522::STATUS_OK) {
                Serial.println("PCD_Authenticate() failed: " + String(this->rfid_scanner.GetStatusCodeName(attempt_auth)));                
                return false;
            }    
            
            Serial.println("Successfully authenticated Key A");          
            return true; 
        }
        
        bool authenticate_key_b(byte trailerBlock) {
          
        }

        bool write_data_to_RFID(byte blockAddr, byte *data) {
            MFRC522::StatusCode write_attempt;

            if (sizeof(data) > MAX_BLOCK_SIZE) {
                Serial.println("Data block is too big!");
                return false; 
            }
            
            write_attempt = this->rfid_scanner.MIFARE_Write(blockAddr, data, MAX_BLOCK_SIZE);            
            
            if (write_attempt != MFRC522::STATUS_OK) {
                Serial.print("MIFARE_Write() failed: ");
                Serial.println(this->rfid_scanner.GetStatusCodeName(write_attempt));
                return false; 
            }
            return true;          
        }

        bool read_data_from_RFID(byte blockAddr) {
            byte size = sizeof(this->read_buffer);   
            MFRC522::StatusCode read_attempt = this->rfid_scanner.MIFARE_Read(blockAddr, this->read_buffer, &size);
            
            // Read data from the block 
            Serial.print("Reading data from block " + String(blockAddr) + "...");             
            
            if (read_attempt != MFRC522::STATUS_OK) {
                Serial.println("MIFARE_Read() failed: " + String(this->rfid_scanner.GetStatusCodeName(read_attempt)));
                return false;
            }          
            return true; 
        }

        bool verify_RFID_write(byte blockAddr, byte *data) {
            byte count = 0;
            
            for (byte i = 0; i < MAX_BLOCK_SIZE; i++) {
                if (this->read_buffer[i] == data[i]) {                 // Compare the read buffer with what was written
                    count++;
                }
            }                        
            if (count == MAX_BLOCK_SIZE) {
                return true;
            } 
            else {
                return false; 
            }   
        }     
                
        void RFID_read_write_test(byte sector, byte blockAddr, byte *data) {
            /*
             * 
             *  Some test code demonstrating how to use this library. Good for debugging as it will dump to serial a variety of helpful 
             */
            byte trailerBlock = 7; // This has to do with the authentication, need to investigate more about why this is.. 
            // byte buffer[18];
            //byte size = sizeof(buffer);                
            MFRC522::StatusCode status;
            
            // perform a test to see if there is a new card on the scanner
            if (!this->rfid_scanner.PICC_IsNewCardPresent()) {
                Serial.println("We previously wrote to this card. If you are sure you want to re-write it, move the card away from the scanner then re-scan");
                return -1;
            }    
        
            // perform a test to see if cards is readable    
            if (!this->rfid_scanner.PICC_ReadCardSerial()) {
                Serial.println("No scanner found, or no card found at scanner");
                return -1;
            }
                
            this->dump_card_uid_to_serial(); // shows the card Unique Identifier
            this->dump_card_picc_type_to_serial();

            // Check for compatibility
            get_picc_type(); // updates this->piccType
            
            if (this->piccType != MFRC522::PICC_TYPE_MIFARE_MINI && this->piccType != MFRC522::PICC_TYPE_MIFARE_1K && this->piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
                Serial.println("This will only work with MIFARE classic cards. Please use a different card.");
                return -1;
            }    
        
            if (!this->authenticate_key_a(trailerBlock)) {
                return -1; 
            }
            
            // Write data to the block
            Serial.print("Writing data into block " + String(blockAddr) + " ...");             
            dump_byte_array_to_serial(data, MAX_BLOCK_SIZE);
            
            if (!write_data_to_RFID(blockAddr, data)) {
                return -1; 
            }
            
            if (!read_data_from_RFID(blockAddr)) {
                return -1;
            }
            
            Serial.print("Data in block " + String(blockAddr) + ": "); 
            dump_byte_array_to_serial(this->read_buffer, MAX_BLOCK_SIZE); 

            // Check that data in block is what we have written by counting the number of bytes that are equal            
            Serial.print("\nVerifying that data was written successfully...");        
            
            if (this->verify_RFID_write(blockAddr, data)) {
                Serial.println("Success!");
            }
            else {
                Serial.println("Error - Data in RFID block does not match input data");
                return -1; 
            }

            // Dump the sector data
            this->dump_sector_data_to_serial(sector);
    
            this->rfid_scanner.PICC_HaltA(); // Halt PICC    
            this->rfid_scanner.PCD_StopCrypto1();    // Stop encryption on PCD
        }

        void dump_card_uid_to_serial(void) {
            Serial.print("\nCard UID:");
            dump_byte_array_to_serial(this->rfid_scanner.uid.uidByte, this->rfid_scanner.uid.size);    
        }
        
        void dump_card_picc_type_to_serial(void) {
            get_picc_type();            
            Serial.println("\nPICC type: " + this->piccTypeName);   
        }

        void dump_sector_data_to_serial(byte sector) {
            Serial.println("\nCurrent data in sector:");
            this->rfid_scanner.PICC_DumpMifareClassicSectorToSerial(&(this->rfid_scanner.uid), &this->key, sector);
            Serial.println();
        }                    
};

/*
 * 
 *  Variables and Constants
 * 
 */

// set up some pins
const uint8_t spi_bus_reset_pin = 10;   
const uint8_t spi_bus_mosi_pin = 11; 
const uint8_t spi_bus_miso_pin = 12; 
const uint8_t spi_bus_sck_pin = 13;  
const uint8_t rfid_scanner_ss = 2;  

// the program will read from the console
const uint8_t ASCII_NEWLINE = 10; 
const uint8_t ASCII_INVALID_CHAR = -1;
byte character_read; 
char rfid_data[MAX_BLOCK_SIZE + 1];
byte read_index = 0; 
String input_message = "\nEnter up to 16 ASCII characters to write to this card: ";

// our wrapper 
mifare_classic_wrapper rfid_scanner;
byte sector = 1; // for this write test, we write data into sector 1, block 4. 
byte blockAddr = 4;

/*
 * 
 *  Example Code 
 *  
 */
 
void setup() { 
    // init our serial comms port    
    Serial.begin(9600);              
    
    pinMode(rfid_scanner_ss, OUTPUT);  
    pinMode(spi_bus_reset_pin, OUTPUT);  // we  don't need to store these.
    SPI.begin();  // ensure you have your SPI bus pins set up on the Arduino Hardware
    rfid_scanner.initialize(rfid_scanner_ss, spi_bus_reset_pin); // ensure that you have run SPI.begin and Serial.begin before use
      
    Serial.println(input_message);    
}


void loop() { 
    if (Serial.available() > 0) {
        character_read = Serial.read();

        if (character_read == ASCII_NEWLINE) {
            Serial.print("Captured: '");      
            Serial.println(String(rfid_data) + "', ASCII data will be written to the card");            

            rfid_scanner.RFID_read_write_test(sector, blockAddr, rfid_data);
                        
            read_index = 0; // restart the array
            for (byte i = 0; i < MAX_BLOCK_SIZE; i++) { // blank the string. 
                rfid_data[i] = '\0'; 
            }

            Serial.println(input_message);             
            return;   // stop reading any more and start again.           
        }
        else if (character_read != ASCII_INVALID_CHAR && read_index < MAX_BLOCK_SIZE) {   
            rfid_data[read_index] = (char)character_read;
            read_index++;
        } 
        else {
            Serial.println("Invalid character entered, or exceeded length. Omitting characater"); 
        }
    }
}

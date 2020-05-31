/*
 * 
 * 
 *   Todo:
 *    - remove the MAX_CARD_DATA_LENGTH limitation which at present is only used for testing purposes. 
 *    - 
 * 
 */

#include <SPI.h>  // Ardino SPI bus library
#include <MFRC522.h> // RFID-RC522 Library - Download from here - https://github.com/miguelbalboa/rfid and click "add to library" to run this example

#define MAX_CARD_DATA_LENGTH 16 // for testing only at this stage. 

/*
 * 
 *  Classes and helper functions
 * 
 */
 
class mifare_classic_wrapper {
  private:
    MFRC522 rfid_scanner;
    MFRC522::MIFARE_Key key;
    const byte KEY_LENGTH = 6; 
    
  public:
    mifare_classic_wrapper() {
      // do nothing
    }
    
    void initialize(byte ss_pin, byte reset_pin) {            
        // init the scanner
        this->rfid_scanner.PCD_Init(ss_pin, reset_pin); 
        
        // Prepare a blank crypto key (used both as key A and as key B) for the encryption needed for writing. Factory default for most cards = FFFFFFFFFFFFh
        for (byte i = 0; i < this->KEY_LENGTH; i++) {
            this->key.keyByte[i] = 0xFF;
        }  
    }
    
    byte check_reader_version(void) {
        // Get the MFRC522 software version
        return this->rfid_scanner.PCD_ReadRegister(this->rfid_scanner.VersionReg);
    }
    
    void dump_byte_array(byte *buffer, byte bufferSize) {
        for (byte i = 0; i < bufferSize; i++) {
            Serial.print(buffer[i] < 0x10 ? " 0" : " "); // Found a pretty clever way of padding 0's and adding spaces in the Mifare library, so I pinched this for my own use. 
            Serial.print(buffer[i], HEX);
        }
    }
    
    void dump_card_uid(void) {
        Serial.print("\nCard UID:");
        dump_byte_array(this->rfid_scanner.uid.uidByte, this->rfid_scanner.uid.size);    
    }
    
    void dump_card_picc_type(void) {
        MFRC522::PICC_Type piccType = this->rfid_scanner.PICC_GetType(this->rfid_scanner.uid.sak);
        Serial.print("\nPICC type: ");   
        Serial.println(this->rfid_scanner.PICC_GetTypeName(piccType));      
    }
    
    void write_RFID_card(byte data[MAX_CARD_DATA_LENGTH]) {
        byte sector = 1; // for this test, we write data into sector 1, block 4. 
        byte blockAddr = 4;
        byte trailerBlock = 7; // todo - investigate more about why this is...
        byte buffer[18];
        byte size = sizeof(buffer); 
           
        MFRC522::StatusCode status;
        MFRC522::PICC_Type piccType;
        
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
            
        this->dump_card_uid(); // shows the card Unique Identifier
        this->dump_card_picc_type();
        piccType = this->rfid_scanner.PICC_GetType(this->rfid_scanner.uid.sak);
            
        // Check for compatibility
        if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
            Serial.println("This will only work with MIFARE classic cards.");
            return -1;
        }    
    
        // Authenticate using key A
        Serial.println("Authenticating using key A...");
        status = (MFRC522::StatusCode) this->rfid_scanner.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &this->key, &(this->rfid_scanner.uid));
        if (status != MFRC522::STATUS_OK) {
            Serial.print("PCD_Authenticate() failed: ");
            Serial.println(this->rfid_scanner.GetStatusCodeName(status));
            return -1;
        }    
        Serial.println("Complete");
        
        // Write data to the block
        Serial.print("Writing data into block "); Serial.print(blockAddr);
        Serial.println(" ...");
        dump_byte_array(data, MAX_CARD_DATA_LENGTH);
        Serial.println();
        status = (MFRC522::StatusCode) this->rfid_scanner.MIFARE_Write(blockAddr, data, MAX_CARD_DATA_LENGTH);
        if (status != MFRC522::STATUS_OK) {
            Serial.print("MIFARE_Write() failed: ");
            Serial.println(this->rfid_scanner.GetStatusCodeName(status));
        }
        Serial.println();
    
        // Read data from the block 
        Serial.print("Reading data from block "); 
        Serial.print(blockAddr);
        Serial.println("...");
        status = (MFRC522::StatusCode) this->rfid_scanner.MIFARE_Read(blockAddr, buffer, &size);
        
        if (status != MFRC522::STATUS_OK) {
            Serial.print("MIFARE_Read() failed: ");
            Serial.println(this->rfid_scanner.GetStatusCodeName(status));
        }
        
        Serial.print("Data in block "); 
        Serial.print(blockAddr); 
        Serial.println(":");
        dump_byte_array(buffer, MAX_CARD_DATA_LENGTH); 
        Serial.println();
    
        // Check that data in block is what we have written by counting the number of bytes that are equal
        Serial.println("\nChecking result...");
        byte count = 0;
        for (byte i = 0; i < MAX_CARD_DATA_LENGTH; i++) {
            // Compare buffer (= what we've read) with dataBlock (= what we've written)
            if (buffer[i] == data[i])
                count++;
        }
        
        Serial.print("Number of bytes that match = "); 
        Serial.println(count);
        
        if (count == MAX_CARD_DATA_LENGTH) {
            Serial.println("Success!");
        } 
        else {
            Serial.println("Failure, no match, perhaps the write didn't work properly...");
        }
    
        // Dump the sector data
        read_and_dump_sector_data(sector);

        this->rfid_scanner.PICC_HaltA(); // Halt PICC    
        this->rfid_scanner.PCD_StopCrypto1();    // Stop encryption on PCD
    }
    
    void read_and_dump_sector_data(byte sector) {
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
char rfid_data[MAX_CARD_DATA_LENGTH + 1];
byte read_index = 0; 
String input_message = "\nEnter up to 8 Hexidecimal characters to write to card: ";

// our wrapper 
mifare_classic_wrapper rfid_scanner;

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
    rfid_scanner.initialize(rfid_scanner_ss, spi_bus_reset_pin);
      
    Serial.println(input_message);    
}


void loop() { 
    if (Serial.available() > 0) {
        character_read = Serial.read();

        if (character_read == ASCII_NEWLINE) {
            Serial.print("Captured: '");      
            Serial.println(String(rfid_data) + "', ASCII data will be written to the card");            

            rfid_scanner.write_RFID_card(rfid_data);
                        
            read_index = 0; // restart the array
            for (byte i = 0; i < MAX_CARD_DATA_LENGTH; i++) { // blank the string. 
                rfid_data[i] = '\0'; 
            }

            Serial.println(input_message);             
            return;   // stop reading any more and start again.           
        }
        else if (character_read != ASCII_INVALID_CHAR && read_index < MAX_CARD_DATA_LENGTH) {   
            rfid_data[read_index] = (char)character_read;
            read_index++;
        } 
        else {
            Serial.println("Invalid character entered, or exceeded length"); 
        }
    }
}

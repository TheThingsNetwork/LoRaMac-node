/** Copyright © 2020 The Things Industries B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file atecc608a-tnglora-se.c
 * Todo: clean up this file before PR, add more checks for status, see https://github.com/TheThingsIndustries/lorawan-example-atecc608a-tnglora/issues/4
 * Todo: add status checks for atca calls, see https://github.com/TheThingsIndustries/lorawan-example-atecc608a-tnglora/issues/4
 * Todo: add SE derivation for multicast keys, see https://github.com/TheThingsIndustries/lorawan-example-atecc608a-tnglora/issues/4
 * Todo: handle dev and join-euis readings from SE slots, see https://github.com/TheThingsIndustries/lorawan-example-atecc608a-tnglora/issues/4
 * Todo: use the secure element random generators, see https://github.com/TheThingsIndustries/lorawan-example-atecc608a-tnglora/issues/4
 * @copyright Copyright (c) 2020 The Things Industries B.V.
 *
 */

#include "secure-element.h"
#include "atca_basic.h"
#include "radio.h"
#include "cryptoauthlib.h"
#include "atca_devtypes.h"

#define NUM_OF_KEYS 10
#define KEY_SIZE 16

#define TNGLORA_NWK_KEY_SLOT 0
#define TNGLORA_APP_KEY_SLOT 0
#define TNGLORA_APP_S_KEY_SLOT 2
#define TNGLORA_NWK_S_ENC_KEY_SLOT 3
#define TNGLORA_S_NWK_S_INT_KEY_SLOT 4
#define TNGLORA_F_NWK_S_INT_KEY_SLOT 5
#define TNGLORA_J_S_INT_KEY_SLOT 6
#define TNGLORA_J_S_ENC_KEY_SLOT 7
#define TNGLORA_MC_APP_S_KEY_0_SLOT 11
#define TNGLORA_MC_NWK_S_KEY_0_SLOT 12
#define TNGLORA_APP_KEY_BLOCK_INDEX 1
#define TNGLORA_REMAINING_KEYS_BLOCK_INDEX 0

/*!
 * Identifier value pair type for Keys
 */
typedef struct sKey
{
    /*
     * Key identifier (used for maping the stack MAC key to the ATECC608A-TNGLoRaWAN slot)
     */
    KeyIdentifier_t KeyID;
    /*
     * Key slot number
     */
    uint16_t KeySlotNumber;
    /*
     * Key block index within slot (each block can contain two keys, so index is either 0 or 1)
     * 
    */
    uint8_t KeyBlockIndex;
    /*
     * Key value
     */
} Key_t;

/*
 * Secure Element Non Volatile Context structure
 */
typedef struct sSecureElementNvCtx
{
    /*
     * DevEUI storage
     */
    uint8_t DevEui[SE_EUI_SIZE];
    /*
     * Join EUI storage
     */
    uint8_t JoinEui[SE_EUI_SIZE];
    /*
     * CMAC computation context variable
     */
    atca_aes_cmac_ctx_t AtcaAesCmacCtx;
    /*
     * Key List
     */
    Key_t KeyList[NUM_OF_KEYS];
} SecureElementNvCtx_t;

/*
 * Module context
 */
static SecureElementNvCtx_t SeNvmCtx;
static ATCAIfaceCfg atecc608_i2c_config;

static SecureElementNvmEvent SeNvmCtxChanged;

/*
 * Gets key item from key list.
 *
 *  cmac = aes128_cmac(keyID, B0 | msg)
 *
 * \param[IN]  keyID          - Key identifier
 * \param[OUT] keyItem        - Key item reference
 * \retval                    - Status of the operation
 */
SecureElementStatus_t GetKeyByID(KeyIdentifier_t keyID, Key_t **keyItem)
{
    for (uint8_t i = 0; i < NUM_OF_KEYS; i++)
    {
        if (SeNvmCtx.KeyList[i].KeyID == keyID)
        {
            *keyItem = &(SeNvmCtx.KeyList[i]);
            return SECURE_ELEMENT_SUCCESS;
        }
    }
    return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
}

/*
 * Dummy callback in case if the user provides NULL function pointer
 */
static void DummyCB(void)
{
    return;
}

/*
 * Computes a CMAC of a message using provided initial Bx block
 *
 *  cmac = aes128_cmac(keyID, blocks[i].Buffer)
 *
 * \param[IN]  micBxBuffer    - Buffer containing the initial Bx block
 * \param[IN]  buffer         - Data buffer
 * \param[IN]  size           - Data buffer size
 * \param[IN]  keyID          - Key identifier to determine the AES key to be used
 * \param[OUT] cmac           - Computed cmac
 * \retval                    - Status of the operation
 */
static SecureElementStatus_t ComputeCmac(uint8_t *micBxBuffer, uint8_t *buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t *cmac)
{
    if ((buffer == NULL) || (cmac == NULL))
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    uint8_t Cmac[16] = {0};

    Key_t *keyItem;
    SecureElementStatus_t retval = GetKeyByID(keyID, &keyItem);
    if (retval != SECURE_ELEMENT_SUCCESS)
    {
        return retval;
    }
    ATCA_STATUS status = atcab_aes_cmac_init(&SeNvmCtx.AtcaAesCmacCtx, keyItem->KeySlotNumber, keyItem->KeyBlockIndex);

    if (ATCA_SUCCESS == status)
    {
        if (micBxBuffer != NULL)
        {
            atcab_aes_cmac_update(&SeNvmCtx.AtcaAesCmacCtx, micBxBuffer, 16);
        }

        atcab_aes_cmac_update(&SeNvmCtx.AtcaAesCmacCtx, buffer, size);

        atcab_aes_cmac_finish(&SeNvmCtx.AtcaAesCmacCtx, Cmac, 16);

        *cmac = (uint32_t)((uint32_t)Cmac[3] << 24 | (uint32_t)Cmac[2] << 16 | (uint32_t)Cmac[1] << 8 | (uint32_t)Cmac[0]);
        return SECURE_ELEMENT_SUCCESS;
    }
    else
    {
        return SECURE_ELEMENT_ERROR;
    }
}

SecureElementStatus_t SecureElementInit(SecureElementNvmEvent seNvmCtxChanged)
{
    uint8_t itr = 0;

    // Initialize with defaults
    SeNvmCtx.KeyList[itr].KeyID = NWK_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_APP_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_APP_KEY_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = APP_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_APP_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_APP_KEY_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = APP_S_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_APP_S_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = NWK_S_ENC_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_NWK_S_ENC_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = S_NWK_S_INT_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_S_NWK_S_INT_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = F_NWK_S_INT_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_F_NWK_S_INT_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = J_S_INT_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_J_S_INT_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = J_S_ENC_KEY;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_J_S_ENC_KEY_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = MC_APP_S_KEY_0;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_MC_APP_S_KEY_0_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    SeNvmCtx.KeyList[itr].KeyID = MC_NWK_S_KEY_0;
    SeNvmCtx.KeyList[itr].KeySlotNumber = TNGLORA_MC_NWK_S_KEY_0_SLOT;
    SeNvmCtx.KeyList[itr++].KeyBlockIndex = TNGLORA_REMAINING_KEYS_BLOCK_INDEX;

    atecc608_i2c_config.iface_type = ATCA_I2C_IFACE;
    atecc608_i2c_config.atcai2c.baud = 100000U;
    atecc608_i2c_config.atcai2c.bus = 2U;
    atecc608_i2c_config.atcai2c.slave_address = 0x59;
    atecc608_i2c_config.devtype = ATECC608A;
    atecc608_i2c_config.rx_retries = 20;
    atecc608_i2c_config.wake_delay = 1500U;

    atcab_init(&atecc608_i2c_config);

    memset1(SeNvmCtx.DevEui, 0, SE_EUI_SIZE);
    memset1(SeNvmCtx.JoinEui, 0, SE_EUI_SIZE);

    // Assign callback
    if (seNvmCtxChanged != 0)
    {
        SeNvmCtxChanged = seNvmCtxChanged;
    }
    else
    {
        SeNvmCtxChanged = DummyCB;
    }

    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementRestoreNvmCtx(void *seNvmCtx)
{
    // Restore nvm context
    if (seNvmCtx != 0)
    {
        memcpy1((uint8_t *)&SeNvmCtx, (uint8_t *)seNvmCtx, sizeof(SeNvmCtx));
        return SECURE_ELEMENT_SUCCESS;
    }
    else
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
}

void *SecureElementGetNvmCtx(size_t *seNvmCtxSize)
{
    *seNvmCtxSize = sizeof(SeNvmCtx);
    return &SeNvmCtx;
}

SecureElementStatus_t SecureElementSetKey(KeyIdentifier_t keyID, uint8_t *key)
{
    // No key setting for HW SE, can only derive keys
    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementComputeAesCmac(uint8_t *micBxBuffer, uint8_t *buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t *cmac)
{
    if (keyID >= LORAMAC_CRYPTO_MULTICAST_KEYS)
    {
        //Never accept multicast key identifier for cmac computation
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }
    return ComputeCmac(micBxBuffer, buffer, size, keyID, cmac);
}

SecureElementStatus_t SecureElementVerifyAesCmac(uint8_t *buffer, uint16_t size, uint32_t expectedCmac, KeyIdentifier_t keyID)
{
    if (buffer == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    SecureElementStatus_t retval = SECURE_ELEMENT_ERROR;
    uint32_t compCmac = 0;
    retval = ComputeCmac(NULL, buffer, size, keyID, &compCmac);
    if (retval != SECURE_ELEMENT_SUCCESS)
    {
        return retval;
    }

    if (expectedCmac != compCmac)
    {
        retval = SECURE_ELEMENT_FAIL_CMAC;
    }

    return retval;
}
SecureElementStatus_t SecureElementAesEncrypt(uint8_t *buffer, uint16_t size, KeyIdentifier_t keyID, uint8_t *encBuffer)
{
    if (buffer == NULL || encBuffer == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    // Check if the size is divisible by 16,
    if ((size % 16) != 0)
    {
        return SECURE_ELEMENT_ERROR_BUF_SIZE;
    }

    Key_t *pItem;
    SecureElementStatus_t retval = GetKeyByID(keyID, &pItem);

    if (retval == SECURE_ELEMENT_SUCCESS)
    {

        uint8_t block = 0;

        while (size != 0)
        {
            atcab_aes_encrypt(pItem->KeySlotNumber, pItem->KeyBlockIndex, &buffer[block], &encBuffer[block]);
            block = block + 16;
            size = size - 16;
        }
    }
    return retval;
}

SecureElementStatus_t SecureElementDeriveAndStoreKey(Version_t version, uint8_t *input, KeyIdentifier_t rootKeyID, KeyIdentifier_t targetKeyID)
{
    if (input == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    //Source key slot is the LSB and target key slot is the MSB
    uint16_t source_target_ids = 0;
    Key_t *source_key;
    Key_t *target_key;
    ATCA_STATUS status = ATCA_SUCCESS;

    // In case of MC_KE_KEY, prevent other keys than NwkKey or AppKey for LoRaWAN 1.1 or later
    if (targetKeyID == MC_KE_KEY)
    {
        if (((rootKeyID == APP_KEY) && (version.Fields.Minor == 0)) || (rootKeyID == NWK_KEY))
        {
            return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
        }
    }

    if (rootKeyID == GEN_APP_KEY || rootKeyID == MC_ROOT_KEY || rootKeyID == MC_KE_KEY)
    {
        // Allow the stack to move forward as these rootkeys dont exist inside SE.
        return SECURE_ELEMENT_SUCCESS; //Todo: add SE derivation for multicast keys.
    }

    if (GetKeyByID(rootKeyID, &source_key) != SECURE_ELEMENT_SUCCESS)
    {
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }

    if (GetKeyByID(targetKeyID, &target_key) != SECURE_ELEMENT_SUCCESS)
    {
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }

    source_target_ids = target_key->KeySlotNumber << 8;
    source_target_ids += source_key->KeySlotNumber;

    uint32_t detail = source_key->KeyBlockIndex;

    status = atcab_kdf(KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_SLOT,
                       source_target_ids, detail, input, NULL, NULL);
    if (status == ATCA_SUCCESS)
    {
        return SECURE_ELEMENT_SUCCESS;
    }
    else
    {
        return SECURE_ELEMENT_ERROR;
    }
}
SecureElementStatus_t SecureElementRandomNumber(uint32_t *randomNum)
{
    if (randomNum == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    *randomNum = Radio.Random(); //Todo: use the secure element random generators
    return SECURE_ELEMENT_SUCCESS;
}
SecureElementStatus_t SecureElementSetDevEui(uint8_t *devEui) //Todo: handle dev and join-euis readings from SE slots
{
    if (devEui == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1(SeNvmCtx.DevEui, devEui, SE_EUI_SIZE);
    SeNvmCtxChanged();
    return SECURE_ELEMENT_SUCCESS;
}
uint8_t *SecureElementGetDevEui(void)
{
    return SeNvmCtx.DevEui;
}
SecureElementStatus_t SecureElementSetJoinEui(uint8_t *joinEui)
{
    if (joinEui == NULL)
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1(SeNvmCtx.JoinEui, joinEui, SE_EUI_SIZE);
    SeNvmCtxChanged();
    return SECURE_ELEMENT_SUCCESS;
}
uint8_t *SecureElementGetJoinEui(void)
{
    return SeNvmCtx.JoinEui;
}
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
 * @file i2c-board.c
 *
 * @copyright Copyright (c) 2020 The Things Industries B.V.
 *
 */
#include <peripheral_clk_config.h>
#include <hal_gpio.h>
#include <hal_i2c_m_sync.h>

#include "board.h"
#include "i2c-board.h"

struct i2c_m_sync_desc I2C_INSTANCE;

void I2cMcuInit(I2c_t *obj, I2cId_t i2cId, PinNames scl, PinNames sda)
{
    obj->I2cId = i2cId;

    // Clock initialization
    hri_gclk_write_PCHCTRL_reg(GCLK, SERCOM1_GCLK_ID_CORE, CONF_GCLK_SERCOM1_CORE_SRC | (1 << GCLK_PCHCTRL_CHEN_Pos));
    hri_gclk_write_PCHCTRL_reg(GCLK, SERCOM1_GCLK_ID_SLOW, CONF_GCLK_SERCOM1_SLOW_SRC | (1 << GCLK_PCHCTRL_CHEN_Pos));

    hri_mclk_set_APBCMASK_SERCOM1_bit(MCLK);

    // I2c initialization
    i2c_m_sync_init(&I2C_INSTANCE, SERCOM1);

    gpio_set_pin_function(sda, PINMUX_PA16C_SERCOM1_PAD0);
    gpio_set_pin_function(scl, PINMUX_PA17C_SERCOM1_PAD1);

    i2c_m_sync_enable(&I2C_INSTANCE);
}

void I2cMcuDeInit(I2c_t *obj)
{
    // Left empty
}

void I2cMcuFormat(I2c_t *obj, I2cMode mode, I2cDutyCycle dutyCycle, bool I2cAckEnable, I2cAckAddrMode AckAddrMode, uint32_t I2cFrequency)
{
    // configured via hpl_sercom_config.h
    return;
}

uint8_t I2cMcuWriteBuffer(I2c_t *obj, uint8_t deviceAddr, uint16_t addr, uint8_t *buffer, uint16_t size)
{
    i2c_m_sync_set_slaveaddr(&I2C_INSTANCE, deviceAddr, I2C_M_SEVEN);
    if (io_write(&I2C_INSTANCE.io, buffer, size) == size)
    {
        return 1; //ok
    }
    else
    {
        return 0; //something went wrong
    }
}

uint8_t I2cMcuReadBuffer(I2c_t *obj, uint8_t deviceAddr, uint16_t addr, uint8_t *buffer, uint16_t size)
{
    i2c_m_sync_set_slaveaddr(&I2C_INSTANCE, deviceAddr, I2C_M_SEVEN);
    if (io_read(&I2C_INSTANCE.io, buffer, size) == size)
    {
        return 1; //ok
    }
    else
    {
        return 0; //something went wrong
    }
}
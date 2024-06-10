# -*- coding: utf-8 -*
__author__ = 'AhnLab ASEC'
__version__ = '1.1'

import idaapi
import idc

ACTION_HAPPY_DECODE = "HappyDecode"

xrange = range

class UIHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        formtype = idaapi.get_widget_type(form)

        if formtype == idaapi.BWN_DISASM or idaapi.BWN_DUMP:
            idaapi.attach_action_to_popup(form, popup, ACTION_HAPPY_DECODE, None)

class PopupActionHandler(idaapi.action_handler_t):
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
    
    def decodeData(data):
        num = 0
        
        for i in data:
            if (i >= ord('0') and i <= ord('9')) or (i >= ord('A') and i <= ord('F')):
                num += 1
                continue

            break

        if num % 2 == 1:
            num -= 1

        if num < 10:
            return False

        data = bytes.fromhex(data[0:num].decode())
        buff_len = len(data) - 3

        target = [0] * len(data)

        for i in range(1, buff_len):
            target[i] = data[4 + i - 1]

        key = [0] * 4

        for i in range(0, 4):
            key[i] = data[i]

        num = 0

        buff = [0] * len(data)
        
        for i in range(0, buff_len - 1):
            buff[i] = key[i % 4] ^ target[i] ^ target[i + 1]

        dec_str = ''.join([chr(c) for c in buff])

        print(dec_str)

        return True

    
    @classmethod
    def decodeHappy(self):
        pos_addr = idc.here()
        
        res = bytes()
        lastVal = bytes()

        for i in range(0, 100):
            cmd = idc.print_insn_mnem(pos_addr)

            if cmd == 'movdqa':
                if idc.get_operand_type(pos_addr, 1) != idc.o_mem:
                    pos_addr = idc.next_head(pos_addr)
                    continue

                xmm_addr = idc.get_operand_value(pos_addr, 1)
                val = idc.get_qword(xmm_addr + 8) * pow(2, 64) + idc.get_qword(xmm_addr)

                val = val.to_bytes(16, byteorder='little')
                lastVal = val
            elif cmd == 'mov':
                if idc.get_operand_type(pos_addr, 1) != idc.o_imm:
                    pos_addr = idc.next_head(pos_addr)
                    continue

                strData = idc.GetDisasm(pos_addr)

                if strData.find("[rsp+") < 0 and strData.find("[rbp+") < 0:
                    pos_addr = idc.next_head(pos_addr)
                    continue

                val = idc.get_operand_value(pos_addr, 1)

                val = val.to_bytes(8, byteorder='little')
                val = val[0:4]
            elif cmd == 'psubb':
                if idc.get_operand_type(pos_addr, 1) != idc.o_mem:
                    pos_addr = idc.next_head(pos_addr)
                    continue

                xmm_addr = idc.get_operand_value(pos_addr, 1)
                val = idc.get_qword(xmm_addr + 8) * pow(2, 64) + idc.get_qword(xmm_addr)

                val = val.to_bytes(16, byteorder='little')
                lastVal = val
            elif cmd == 'jb':
                break
            else:
                pos_addr = idc.next_head(pos_addr)
                continue
            
            res = res + val

            pos_addr = idc.next_head(pos_addr)

        res = bytearray(res)
        size = len(res)

        buf = res.copy()

        for i in range(0, size - 1):
            buf[i + 1] = buf[i + 1] ^ (buf[0] % 256)

        flag = self.decodeData(bytes(buf[1:]))

        if flag:
            return
        
        buf = res.copy()
        
        for i in range(0, size - 1):
            buf[i + 1] = buf[i + 1] ^ ((buf[0] + i) % 256)

        flag = self.decodeData(bytes(buf[1:]))

        if flag:
            return
        
        buf = res.copy()[:-0x10]
        size = int(len(buf) / 0x10)
        buf2 = bytes()

        if len(buf) % 0x10 > 0:
            size += 1

        lastVal = int.from_bytes(lastVal, 'little')

        for i in range(0, size):
            pos = i * 0x10
            data = buf[pos:pos + 0x10]
            data = int.from_bytes(bytes(data), 'little')
            data -= lastVal
            buf2 += data.to_bytes(0x10, 'little', signed=True)

        try:
            if buf2[0:8].decode().isprintable():
                print(buf2)
        except:
            pass

        flag = self.decodeData(bytes(buf2))
              
    def activate(self, ctx):
        if self.action == ACTION_HAPPY_DECODE:
            self.decodeHappy()
        else:
            return 0
        
        print(f"==============================================")     

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class happyDecode(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""

    help = ""
    wanted_name = "HappyDecode"

    def init(self):
        self.hexrays_inited = False
        self.reg_actions = []

        actions = (
            idaapi.action_desc_t(ACTION_HAPPY_DECODE, "HappyDecode", PopupActionHandler(ACTION_HAPPY_DECODE), "Shift+H", None, 38),
        )

        for i in actions:
            idaapi.register_action(i)
            self.reg_actions.append(i.name)

        self.ui_hook = UIHook()
        self.ui_hook.hook()

        return idaapi.PLUGIN_KEEP
        
    def run(self, arg):
        pass

    def term(self):
        if self.ui_hook:
            self.ui_hook.unhook()

        for i in self.reg_actions:
            idaapi.unregister_action(i)
    
def PLUGIN_ENTRY():
    return happyDecode()

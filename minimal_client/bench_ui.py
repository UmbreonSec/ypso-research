"""Use mylife to select only the recorded pump."""
import asyncio

from .bench import validate_target
from .ui import UI
from .relay_wire import APP

PREFIX=APP+':id/'


class BenchNativeUI(UI):
    def __init__(self,device,target):
        if device.role!='usual_phone':raise ValueError('Recorded usual phone required')
        validate_target(target)
        super().__init__(device)
        self.label=target['name'].replace('_',' ',1)
        self.last_nodes=[]

    def entries(self,nodes):
        return [n.get('text') for n in nodes if n.get('resource-id')==PREFIX+'Settings_DeviceList_Item_Text']

    async def management(self):
        await self.launch(APP);unexpected=0
        async with asyncio.timeout(100):
            while True:
                ns=await self.nodes();self.last_nodes=ns;ts=self.texts(ns)
                if any(n.get('content-desc')=='Close navigation drawer' for n in ns):
                    found=[n for n in ns if n.get('text')=='Settings' and n.get('resource-id')==PREFIX+'design_menu_item_text']
                    if len(found)!=1:raise RuntimeError('Unique genuine-app settings entry required')
                    await self.tap(found[0],{APP})
                elif 'Found devices' in ts:
                    await self.text(ns,'Cancel',{APP})
                elif any('optimisation of battery' in t for t in ts):
                    await self.resource(ns,PREFIX+'Popup_cMessageDialog_SecondButton',{APP})
                elif any(t.startswith('Please open your smartphone settings. For the mylife App, enable the Bluetooth permission') for t in ts):
                    # Dismiss the message without granting permission.
                    await self.resource(ns,PREFIX+'Popup_cMessageDialog_Confirm',{APP})
                elif 'Device management' in ts and ('Add YpsoPump' in ts or self.entries(ns)):
                    return ns
                elif any(n.get('resource-id')==PREFIX+'ypsoPumpTitle' for n in ns):
                    await self.d.shell('input','keyevent','BACK')
                elif 'Device management' in ts:
                    await self.text(ns,'Device management',{APP})
                else:
                    opened=[n for n in ns if n.get('content-desc')=='Open navigation drawer']
                    if len(opened)==1:await self.tap(opened[0],{APP})
                    else:
                        unexpected+=1
                        if unexpected>=4:raise RuntimeError('Unexpected genuine-app state before device management')
                        await asyncio.sleep(.4)

    async def find(self):
        ns=await self.management()
        if self.entries(ns):raise RuntimeError('Preexisting configured devices; no automated replacement')
        await self.text(ns,'Add YpsoPump',{APP})
        async with asyncio.timeout(100):
            while True:
                ns=await self.nodes();ts=self.texts(ns)
                if 'Found devices' in ts:
                    entries=[n.get('text') for n in ns if n.get('resource-id')==PREFIX+'DevicesList_Popup_Label']
                    if entries.count(self.label)!=1:
                        await self.text(ns,'Cancel',{APP})
                        raise RuntimeError('Exact physical target not uniquely present; no selection')
                    return
                buttons=[n for n in ns if n.get('resource-id')==PREFIX+'ypsoPumpNextBtn']
                if len(buttons)==1:await self.tap(buttons[0],{APP})
                elif 'Searching your YpsoPump...' in ts:await asyncio.sleep(.3)
                else:raise RuntimeError('Unexpected physical-pump discovery state')

    async def add(self):
        ns=await self.nodes();ts=self.texts(ns)
        entries=[n.get('text') for n in ns if n.get('resource-id')==PREFIX+'DevicesList_Popup_Label']
        if 'Found devices' not in ts or entries.count(self.label)!=1:
            raise RuntimeError('Exact physical target selection not verified')
        await self.text(ns,self.label,{APP})
        ns=await self.nodes()
        if 'Found devices' not in self.texts(ns) or 'Add Device' not in self.texts(ns):
            raise RuntimeError('Unexpected physical-pump add dialog')
        await self.text(ns,'Add Device',{APP})

    async def remove_created_entry(self,*,this_run_selected_target,nearby_denied):
        if not this_run_selected_target or not nearby_denied:
            raise RuntimeError('Removal requires this-run provenance and Bluetooth permission isolation')
        ns=await self.management();entries=self.entries(ns)
        if not entries:return {'this_run_entry_absent':True,'other_devices_modified':False}
        if entries!=[self.label]:raise RuntimeError('Unexpected configured devices; no removal')
        await self.text(ns,self.label,{APP});ns=await self.nodes()
        if self.label not in self.texts(ns) or 'Remove device' not in self.texts(ns):
            raise RuntimeError('Exact target removal page required')
        await self.text(ns,'Remove device',{APP})
        for _ in range(3):
            ns=await self.nodes();ts=self.texts(ns)
            if any(t in ts for t in ['Remove device?','Remove active device?']):
                await self.resource(ns,PREFIX+'Popup_DeleteActiveDevice_Delete',{APP})
            elif 'Device management' in ts and not self.entries(ns):
                return {'this_run_entry_absent':True,'other_devices_modified':False,'pump_bond_removed':False}
            else:raise RuntimeError('Unexpected physical test entry removal state')
        raise RuntimeError('Physical test entry removal not confirmed')

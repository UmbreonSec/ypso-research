package org.ypso.research.benchclient;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.*;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.WindowManager;
import android.widget.TextView;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;

/** One exact already-bonded bench pump. NO NEW_KEY, scan, bond, delivery or clock. */
public final class MainActivity extends Activity {
    private static final String BASE="fb349b5f-8000-0080-0010-0000adde0000";
    private static final String CRYPTO="fb349b5f-8000-0080-0010-0000feda0002";
    private static final String CONTROL="fb349b5f-8000-0080-0010-0000feda0000";
    private static final String P="669a0c20-0008-969e-e211-";
    private static final String PASSWORD=P+"fcbeb2147bc5", AUTHORIZATION=P+"fcff0000000b";
    private static final String EXTENDED=P+"fcff000000ff", STATUS=P+"fcbee48b7bc5";
    private static final Set<String> METADATA=new HashSet<>(Arrays.asList(
        P+"fcbeb0147bc5",P+"fcbeb1147bc5",P+"fcbee23b7bc5",P+"fcbee33b7bc5",P+"fcbee43b7bc5"));
    private final Handler handler=new Handler(Looper.getMainLooper());
    private BluetoothGatt gatt;
    private JSONObject config,command;
    private String session,pendingUuid,mode;
    private long lastId;
    private boolean busy,connectionUsed,passwordSet,statusStarted;
    private int authorizationFrames;
    private int lastGattStatus=-1;
    private String bridgeError;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);TextView text=new TextView(this);
        text.setText("Bench status bridge\nExact recorded bonded pump only.\nNo new-key, delivery or clock commands.");
        setContentView(text);dispatch();
    }
    @Override public void onNewIntent(Intent intent) {super.onNewIntent(intent);setIntent(intent);dispatch();}
    private void dispatch() {
        if(getIntent().getBooleanExtra("permissions_only",false)) {
            if(checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.BLUETOOTH_CONNECT},1);
            else permissionReport(true);
        } else if(getIntent().hasExtra("session"))accept();
    }
    private void permissionReport(boolean granted) {
        try(FileOutputStream out=openFileOutput("permissions.json",MODE_PRIVATE)) {
            out.write(("{\"granted\":"+granted+"}").getBytes(StandardCharsets.UTF_8));
        } catch(Exception ignored) {}
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] grants) {
        super.onRequestPermissionsResult(request,permissions,grants);
        permissionReport(request==1&&grants.length==1&&grants[0]==PackageManager.PERMISSION_GRANTED);
    }
    private JSONObject load(String name)throws Exception {
        File file=new File(getFilesDir(),name+".json");
        if(file.length()>65536)throw new IllegalArgumentException("Input bound");
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(InputStream in=new FileInputStream(file)) {byte[] b=new byte[4096];for(int n;(n=in.read(b))!=-1;)out.write(b,0,n);}
        return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));
    }
    private void accept() {
        try {
            JSONObject next=load("config"),incoming=load("command");String requested=getIntent().getStringExtra("session");
            if(!requested.equals(next.getString("session"))||!requested.equals(incoming.getString("session")))return;
            UUID.fromString(requested);
            if(!requested.equals(session)) {
                closeGatt();session=requested;lastId=0;connectionUsed=false;passwordSet=false;statusStarted=false;authorizationFrames=0;
            }
            if(incoming.getLong("id")<=lastId)return;
            String operation=incoming.getString("op");if(busy&&!"disconnect".equals(operation))return;
            config=next;command=incoming;mode=config.getString("mode");lastGattStatus=-1;bridgeError=null;
            if(!"physical-bench".equals(config.getString("scope"))||
                !("bench-metadata".equals(mode)||"bench-status".equals(mode)||"bench-resume".equals(mode)))throw new IllegalArgumentException("Scope");
            if("bench-resume".equals(mode)) {
                UUID.fromString(config.getString("resume_generation"));
                if(config.has("authorization_hex"))throw new IllegalArgumentException("Resume cannot carry authorization");
            }
            long remaining=config.getLong("expires_ms")-System.currentTimeMillis();
            if(remaining<=0||remaining>120000)throw new IllegalArgumentException("Expired session");
            if(checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED)
                throw new IllegalStateException("Normal Nearby permission required");
            lastId=incoming.getLong("id");busy=true;handler.removeCallbacksAndMessages(null);
            handler.postDelayed(new Runnable(){@Override public void run(){closeGatt();reply(false,null);}},
                "connect".equals(operation)?15000:6000);
            if("disconnect".equals(operation)){closeGatt();reply(true,null);return;}
            if("connect".equals(operation)) {
                if(connectionUsed)throw new IllegalStateException("No reconnect");connectionUsed=true;
                byte[] address=decode(config.getString("peer").replace(":",""));
                if(address.length!=6||!hex(MessageDigest.getInstance("SHA-256").digest(address)).equals(config.getString("peer_sha256")))
                    throw new IllegalArgumentException("Peer pin");
                String name=config.getString("expected_name");
                if(!name.matches("YpsoPump_[0-9]{8}")||Integer.parseInt(name.substring(9))<=10000000)
                    throw new IllegalArgumentException("Physical target required");
                int number=Integer.parseInt(name.substring(9))%10000000;
                byte[] logical=new byte[]{(byte)0xEC,0x2A,(byte)0xF0,(byte)(number>>16),(byte)(number>>8),(byte)number};
                if(!Arrays.equals(address,logical))throw new IllegalArgumentException("Unverified identity mapping");
                BluetoothAdapter adapter=((BluetoothManager)getSystemService(BLUETOOTH_SERVICE)).getAdapter();
                if(adapter==null||!adapter.isEnabled())throw new IllegalStateException("Bluetooth unavailable");
                BluetoothDevice peer=adapter.getRemoteDevice(config.getString("peer"));
                if(peer.getBondState()!=BluetoothDevice.BOND_BONDED||!name.equals(peer.getName()))
                    throw new IllegalArgumentException("Exact preexisting bond/name required");
                gatt=peer.connectGatt(this,false,callbacks,BluetoothDevice.TRANSPORT_LE);
                if(gatt==null)throw new IllegalStateException("GATT unavailable");return;
            }
            if(gatt==null)throw new IllegalStateException("Disconnected");
            if("catalog".equals(operation)) {
                if(!"bench-metadata".equals(mode))throw new IllegalArgumentException("Metadata mode required");
                JSONArray data=new JSONArray();
                for(BluetoothGattService s:gatt.getServices())for(BluetoothGattCharacteristic c:s.getCharacteristics()){
                    JSONObject item=new JSONObject();item.put("service",s.getUuid().toString());item.put("characteristic",c.getUuid().toString());item.put("properties",c.getProperties());data.put(item);
                }
                reply(true,data.toString().getBytes(StandardCharsets.UTF_8));return;
            }
            pendingUuid=incoming.getString("uuid");
            boolean metadata=METADATA.contains(pendingUuid);
            boolean statusRead=("bench-status".equals(mode)||"bench-resume".equals(mode))&&(STATUS.equals(pendingUuid)||EXTENDED.equals(pendingUuid));
            boolean password=PASSWORD.equals(pendingUuid),authorization="bench-status".equals(mode)&&AUTHORIZATION.equals(pendingUuid);
            if("read".equals(operation)) {
                if(!metadata&&!statusRead)throw new IllegalArgumentException("Read forbidden; NEW_KEY never permitted");
                if(statusRead&&(!passwordSet||("bench-status".equals(mode)&&authorizationFrames!=7)))throw new IllegalStateException("Status access not established");
                if(STATUS.equals(pendingUuid)){if(statusStarted)throw new IllegalStateException("One status only");statusStarted=true;}
                if(EXTENDED.equals(pendingUuid)&&!statusStarted)throw new IllegalStateException("No pending status");
            } else if("write".equals(operation)) {
                if(!password&&!authorization)throw new IllegalArgumentException("Write forbidden");
                byte[] value=decode(incoming.getString("hex"));
                if(password) {
                    byte[] address=decode(config.getString("peer").replace(":",""));
                    byte[] salt=new byte[]{79,(byte)194,69,77,(byte)155,(byte)129,89,(byte)164,(byte)147,(byte)187};
                    ByteArrayOutputStream input=new ByteArrayOutputStream();input.write(address);input.write(salt);
                    if(passwordSet||!Arrays.equals(value,MessageDigest.getInstance("MD5").digest(input.toByteArray())))
                        throw new IllegalArgumentException("Access password/sequence");
                } else {
                    byte[] expected=decode(config.getString("authorization_hex"));
                    if(expected.length!=116||!passwordSet||authorizationFrames>=7)throw new IllegalArgumentException("Candidate/sequence");
                    int start=authorizationFrames*19,length=Math.min(19,116-start);byte[] frame=new byte[length+1];
                    frame[0]=(byte)(((authorizationFrames+1)<<4)|7);System.arraycopy(expected,start,frame,1,length);
                    if(!Arrays.equals(frame,value))throw new IllegalArgumentException("Exact candidate fragment required");
                }
            } else throw new IllegalArgumentException("Unknown operation");
            BluetoothGattCharacteristic characteristic=null;
            for(BluetoothGattService s:gatt.getServices()) {
                BluetoothGattCharacteristic c=s.getCharacteristic(UUID.fromString(pendingUuid));
                if(c!=null){if(characteristic!=null)throw new IllegalStateException("Ambiguous characteristic");characteristic=c;}
            }
            if(characteristic==null)throw new IllegalStateException("Missing characteristic");
            if("read".equals(operation)){if(!gatt.readCharacteristic(characteristic))throw new IllegalStateException("Read not queued");}
            else if(gatt.writeCharacteristic(characteristic,decode(incoming.getString("hex")),BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)!=0)
                throw new IllegalStateException("Write not queued");
        }catch(Exception error){bridgeError=error.getMessage();reply(false,null);}
    }
    private final BluetoothGattCallback callbacks=new BluetoothGattCallback(){
        @Override public void onConnectionStateChange(BluetoothGatt g,int status,int state){
            if(g!=gatt||!busy)return;
            lastGattStatus=status;
            if(status!=0||state==BluetoothProfile.STATE_DISCONNECTED){closeGatt();reply(false,null);}
            else if(state==BluetoothProfile.STATE_CONNECTED&&!g.discoverServices())reply(false,null);
        }
        @Override public void onServicesDiscovered(BluetoothGatt g,int status){
            lastGattStatus=status;
            if(g==gatt&&busy&&"connect".equals(command.optString("op")))
                reply(status==0&&g.getService(UUID.fromString(BASE))!=null&&g.getService(UUID.fromString(CRYPTO))!=null&&g.getService(UUID.fromString(CONTROL))!=null,null);
        }
        @Override public void onCharacteristicRead(BluetoothGatt g,BluetoothGattCharacteristic c,byte[] value,int status){
            lastGattStatus=status;
            if(g==gatt&&busy&&"read".equals(command.optString("op"))&&c.getUuid().toString().equals(pendingUuid))reply(status==0&&value.length<=20,value);
        }
        @Override public void onCharacteristicWrite(BluetoothGatt g,BluetoothGattCharacteristic c,int status){
            lastGattStatus=status;
            if(g==gatt&&busy&&"write".equals(command.optString("op"))&&c.getUuid().toString().equals(pendingUuid)){
                if(status==0){if(PASSWORD.equals(pendingUuid))passwordSet=true;else if(AUTHORIZATION.equals(pendingUuid))authorizationFrames++;}
                reply(status==0,null);
            }
        }
    };
    private void reply(boolean ok,byte[] value){
        if(command==null||session==null)return;handler.removeCallbacksAndMessages(null);busy=false;if(!ok)closeGatt();
        try{
            JSONObject result=new JSONObject();result.put("session",session);result.put("id",command.getLong("id"));result.put("ok",ok);result.put("hex",value==null?"":hex(value));
            result.put("gatt_status",lastGattStatus);result.put("operation",command.optString("op"));result.put("bridge_error",bridgeError);
            File file=new File(getFilesDir(),"reply.tmp");try(FileOutputStream out=new FileOutputStream(file)){out.write(result.toString().getBytes(StandardCharsets.UTF_8));}
            if(!file.renameTo(new File(getFilesDir(),"reply.json")))throw new IOException("Atomic reply failed");
            if(gatt!=null)handler.postDelayed(new Runnable(){@Override public void run(){closeGatt();}},30000);
        }catch(Exception ignored){closeGatt();}
    }
    private void closeGatt(){BluetoothGatt old=gatt;gatt=null;if(old!=null){old.disconnect();old.close();}}
    @Override public void onDestroy(){handler.removeCallbacksAndMessages(null);closeGatt();super.onDestroy();}
    private static byte[] decode(String value){if(!value.matches("(?:[0-9a-fA-F]{2})*"))throw new IllegalArgumentException("Hex");byte[] out=new byte[value.length()/2];for(int i=0;i<out.length;i++)out[i]=(byte)Integer.parseInt(value.substring(2*i,2*i+2),16);return out;}
    private static String hex(byte[] value){StringBuilder out=new StringBuilder();for(byte b:value)out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();}
}

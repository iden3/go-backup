package com.example.backup;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import backuplib.*;
import android.util.Log;

import java.io.File;

public class MainActivity extends AppCompatActivity {

    Button restoreButton;
    Button backupButton;

    String folder, backupFile;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        restoreButton = new Button(this);
        backupButton = new Button(this);

        restoreButton  = (Button)findViewById((R.id.button));
        backupButton = (Button)findViewById((R.id.button2));

        folder  = getApplicationContext().getFilesDir().getAbsolutePath()+"/";
        backupFile = folder+"backup.bk";
    }


    // On push button, Restore Backup
    public void clickEventRestore(View v) {
        Backuplib.init();
        File f = new File(backupFile);
        long ncustodians = 0;
        if (f.exists()) {
           Log.d("Backuplib", "Restore Start from backupfile "+backupFile);

           try {
              Backuplib.decodeUnencrypted(backupFile);
              Log.d("Backuplib", "Decode Unencrypted OK");

              Custodians custodians = Backuplib.getSecretCustodians();
              ncustodians = Backuplib.getNCustodians();
              Log.d("Backuplib", "Number of Custodians: "+String.valueOf(ncustodians));
              for (int i=0; i<ncustodians; i++){
                 Custodian custodian = Backuplib.getCustodian(i);
                 Log.d("Backuplib", "Custodian["+String.valueOf(i)+"] Nickname : "+custodian.getNickname());
                 Log.d("Backuplib", "Custodian["+String.valueOf(i)+"] N Shares : "+String.valueOf(custodian.getN_shares()));
                 Log.d("Backuplib", "Custodian["+String.valueOf(i)+"] Fname : "+custodian.getFname());
              }

              Secret secret = Backuplib.getSecretCfg();
              Log.d("Backuplib", "Secret CFG - Max N Shares : "+String.valueOf(secret.getMaxShares()));
              Log.d("Backuplib", "Secret CFG - Min N Shares : "+String.valueOf(secret.getMinShares()));
              Log.d("Backuplib", "Secret CFG - Eelemt Type : "+String.valueOf(secret.getElType()));
           
              byte[] Id = Backuplib.getId();
              

          } catch (Exception e){
              Log.d("Backuplib", "Error Decode Unencrypted");
          }


          if (ncustodians > 0) {
            Log.d("Backuplib", "No custodians available");
            Intent scanQR = new Intent(getApplicationContext(), Restore.class);

            startActivity(scanQR);
          }
        } else {
           Log.d("Backuplib", "Backup file "+backupFile+" doesnt exist");
       }
    }

    // On bpush button, Backup wallet
    public void clickEventBackup(View v) {
        // Initlaize library
        Backuplib.init();
        // Delete old files in local storage
        deleteOldFiles();
       
        Intent genQR = new Intent(getApplicationContext(), ScanQr.class);
        
        startActivity(genQR);
    }

    private void deleteOldFiles(){
        File folderF =new File(folder);
        File[] listOfFiles = folderF.listFiles();
        for (int i=0; i < listOfFiles.length; i++){
            listOfFiles[i].delete();
        }
    }
}

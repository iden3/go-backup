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

    Custodians custodians;


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
        custodians = Backuplib.getCustodians();
    }



    public void clickEventRestore(View v) {
        Backuplib.init();
        System.out.println(backupFile);
        File folderF =new File(folder);
        File[] listOfFiles = folderF.listFiles();

        Log.d("Restore", "Start");
        try {
            Backuplib.decodeUnencrypted(backupFile);
            Log.d("Decode", "OK");

        } catch (Exception e){
            Log.d("Decode", "Error Decode Unencrypted");
        }



        if (Backuplib.getNCustodians() > 0) {
            Intent scanQR = new Intent(getApplicationContext(), Restore.class);

            startActivity(scanQR);
        }
    }

    public void clickEventBackup(View v) {
        Backuplib.init();
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

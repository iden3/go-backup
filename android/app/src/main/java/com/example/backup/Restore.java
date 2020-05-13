package com.example.backup;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.KeyEventDispatcher;

import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.File;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import backuplib.*;

public class Restore extends AppCompatActivity {

    Button scanQRButton, restoreButton;
    TextView displayedNSharesTV, warningTV, qrNameTV, nSharesTV;
    ImageView qrcodeIV;

    String backupFile, folder;

    Secret secret_cfg = Backuplib.getSecretCfg();
    Integer nshares = new Integer(0);
    Long maxShares = secret_cfg.getMaxShares();
    Long minShares = secret_cfg.getMinShares();

    int ncustodians = (int) Backuplib.getNCustodians();

    Integer[] custodian_sequence = new Integer[ncustodians];
    int custodian_idx = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_restore);

        scanQRButton = new Button(this);
        restoreButton = new Button(this);

        displayedNSharesTV = new TextView(this);
        warningTV = new TextView(this);
        qrNameTV = new TextView(this);
        nSharesTV = new TextView(this);

        qrcodeIV = new ImageView(this);

        scanQRButton  = (Button)findViewById((R.id.button5));
        restoreButton = (Button)findViewById((R.id.button4));

        displayedNSharesTV = (TextView)findViewById(R.id.textView7);
        warningTV = (TextView)findViewById(R.id.textView8);
        qrNameTV = (TextView)findViewById(R.id.textView9);
        nSharesTV = (TextView)findViewById(R.id.textView10);

        qrcodeIV = (ImageView)findViewById(R.id.image2);
        updateNSharesTV();

        folder  = getApplicationContext().getFilesDir().getAbsolutePath()+"/";
        backupFile = folder+"backup.bk";


        randomizeCustodian();

    }


    private void randomizeCustodian() {
        for (int i =0 ; i < ncustodians; i++){
            custodian_sequence[i] = i;
        }
        List<Integer> tmpList = Arrays.asList(custodian_sequence);
        Collections.shuffle(tmpList);
        tmpList.toArray(custodian_sequence);
        System.out.println(Arrays.toString(custodian_sequence));

        qrNameTV.setText("");

    }

    private void updateNSharesTV() {
        String nshares_string = String.valueOf(nshares) + "/" + String.valueOf(minShares) + "/" + String.valueOf(maxShares);
        nSharesTV.setText(nshares_string);

    }
    public void clickEventScanQR(View v) {
        Log.d("N custodians", String.valueOf(ncustodians));
        if (custodian_idx < ncustodians) {
            Custodian custodian = Backuplib.getCustodian(custodian_sequence[custodian_idx]);
            String custodian_name = custodian.getNickname();
            long custodian_nshares = custodian.getN_shares();
            String fname = custodian.getFname();
            File qrFile = new File(fname);

            Backuplib.scanQRShare(fname);

            if (qrFile.exists()) {
                Bitmap qrBitmap = BitmapFactory.decodeFile(qrFile.getAbsolutePath());

                qrBitmap = Bitmap.createScaledBitmap(qrBitmap,qrcodeIV.getMeasuredWidth(), qrcodeIV.getMeasuredHeight(), true);
                qrcodeIV.setImageBitmap(qrBitmap);
                qrNameTV.setText(custodian_name);
            }

            custodian_idx++;
            nshares += (int)custodian_nshares;

            updateNSharesTV();
        } else {
            warningTV.setText("There are no more custodians");
        }

    }

    public void clickEventRestore(View v) {

        if (nshares >= minShares) {
            // Generate Key
            Backuplib.setkOp(Backuplib.generateKey());
            Log.d("kOp", new String(Backuplib.getkOp()));
            // Decode and Decrypt backup file -> With the generated kOp, try to decrypt file.
            //   kOp is not used directly. We use a Key Derivation Function. All parameters for this
            //   function are public (except for the Key) and are in the encryption block header
            try {
                Backuplib.decodeEncrypted(backupFile, Backuplib.getkOp());
                Log.d("Decode", "Decode Encrypted OK");
                Intent Home = new Intent(getApplicationContext(), MainActivity.class);
                startActivity(Home);

            } catch (Exception e) {
                Log.d("Decode", "Error Decode Encrypted");
                warningTV.setText("Error during decryption");
            }


        } else {
            warningTV.setText("You need to scan at least "+minShares.toString()+" shares to recover key");
        }
    }


}
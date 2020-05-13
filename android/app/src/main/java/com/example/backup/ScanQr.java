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
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.File;

import backuplib.*;

public class ScanQr extends AppCompatActivity {

    Button genQRButton, homeButton;
    TextView enterNameTV, enterNSharesTV, totalNSharesTV, displayedNSharesTV, warningTV, qrNameTV;
    EditText nameET, nSharesET;
    ImageView qrcodeIV;

    Secret secret_cfg = Backuplib.getSecretCfg();
    Integer nshares = new Integer(0);
    Long maxShares = secret_cfg.getMaxShares();
    Long minShares = secret_cfg.getMinShares();
    String folder, backupFile;

    byte[] kOp;
    byte[] iD;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_scan_qr);

        genQRButton = new Button(this);
        homeButton = new Button(this);

        enterNameTV = new TextView(this);
        enterNSharesTV = new TextView(this);
        totalNSharesTV = new TextView(this);
        displayedNSharesTV = new TextView(this);
        warningTV = new TextView(this);
        qrNameTV = new TextView(this);

        nameET = new EditText(this);
        nSharesET = new EditText(this);

        qrcodeIV = new ImageView(this);

        genQRButton  = (Button)findViewById((R.id.button3));
        homeButton = (Button)findViewById((R.id.button4));

        enterNameTV = (TextView)findViewById(R.id.textView);
        enterNSharesTV = (TextView)findViewById(R.id.textView2);
        totalNSharesTV = (TextView)findViewById(R.id.textView4);
        displayedNSharesTV = (TextView)findViewById(R.id.textView3);
        warningTV = (TextView)findViewById(R.id.textView5);
        qrNameTV = (TextView)findViewById(R.id.textView6);

        nameET = (EditText)findViewById(R.id.editText);
        nSharesET = (EditText)findViewById(R.id.editText2);

        qrcodeIV = (ImageView)findViewById(R.id.image);

        updateNSharesTV();
        qrNameTV.setText("");

        folder  = getApplicationContext().getFilesDir().getAbsolutePath()+"/";
        backupFile = folder+"backup.bk";


        byte[] kOp = Backuplib.keyOperational();
        Backuplib.setkOp(kOp);
        Log.d("KOP", new String(kOp));

        byte[] iD = Backuplib.newID();
        Backuplib.setId(iD);
        Log.d("ID", new String(iD));

        Backuplib.generateShares(kOp);

    }

    private void updateNSharesTV() {
        String nshares_string = String.valueOf(nshares) + "/" + String.valueOf(minShares) + "/" + String.valueOf(maxShares);
        displayedNSharesTV.setText(nshares_string);

    }
    public void clickEventGenQR(View v) {

        String custodian_name = nameET.getText().toString();

        Integer nSharesToCreate;

        try {
            nSharesToCreate = new Integer(nSharesET.getText().toString()).intValue();
        } catch (Exception e) {
            nSharesToCreate = 0;
        }
        String folder  = getApplicationContext().getFilesDir().getAbsolutePath()+"/";
        Log.d("Folder",folder);
        if (nSharesToCreate + nshares <= maxShares &&
                nSharesToCreate > 0 &&
                custodian_name.length() > 0) {
            try {
                // assign first share
                Backuplib.addCustodian(custodian_name, folder, Backuplib.QR, nshares, nSharesToCreate);
            } catch (Exception e) {
                Log.d("Error Adding Custodian", custodian_name);
            }
            nshares+=nSharesToCreate;
            updateNSharesTV();
            warningTV.setText("");
            File qrFile = new File(folder+"qr-"+custodian_name+".png");

            if (qrFile.exists()) {
                Bitmap qrBitmap = BitmapFactory.decodeFile(qrFile.getAbsolutePath());

                qrBitmap = Bitmap.createScaledBitmap(qrBitmap,qrcodeIV.getMeasuredWidth(), qrcodeIV.getMeasuredHeight(), true);
                qrcodeIV.setImageBitmap(qrBitmap);
                qrNameTV.setText("qr-"+custodian_name+".png");

            }
        }  else if (nSharesToCreate + nshares > maxShares){
            warningTV.setText("Too many shares!!");
        }  else if (custodian_name.length() == 0) {
            warningTV.setText("Enter Custodian Name");
        }  else if (nSharesToCreate == 0) {
            warningTV.setText("You need to create at least 1 share");
        }

        nSharesET.setText("");
        nameET.setText("");
    }

    public void clickEventHome(View v) {

        if (nshares >= minShares) {

            Backuplib.addToBackup(Backuplib.CLAIMS, Backuplib.ENCRYPT);
            // Add wallet configuration
            Backuplib.addToBackup(Backuplib.WALLET_CONFIG, Backuplib.ENCRYPT);
            // Add generated ZKP
            Backuplib.addToBackup(Backuplib.ZKP_INFO, Backuplib.ENCRYPT);
            // Add Merkle Tree -> If we haven't created any claims, we don't need to store
            // Merkle Tree because we could regenerate it
            Backuplib.addToBackup(Backuplib.MERKLE_TREE, Backuplib.ENCRYPT);
            // Add Custodian information (contact details) -> unencrypted
            Backuplib.addToBackup(Backuplib.CUSTODIAN, Backuplib.DONT_ENCRYPT);
            // Add Genesis ID) -> unencrypted
            Backuplib.addToBackup(Backuplib.GENID, Backuplib.DONT_ENCRYPT);
            // Add SSharing info. We need Prime number and protocol used (Shamir) -> unencrypted
            Backuplib.addToBackup(Backuplib.SSHARING, Backuplib.DONT_ENCRYPT);
            // Add Shares. We heed to keep a list of at least outstanding shares in case
            //  we want to redistribute in the future. in this example I keep all for simplicity.
            Backuplib.addToBackup(Backuplib.SHARES, Backuplib.ENCRYPT);

            // Generate Backupfile -> Here we select the Key derivation algo and the encryption mechanism used
            //  for encrypted sections. Also not, that we can mix encrypted and non-encrpyted information in the
            // same baclup file
            Backuplib.createBackup(Backuplib.PBKDF2_KEY, Backuplib.SHA256_HASH, Backuplib.GCM_ENCRYPTION, backupFile, kOp);
            Log.d("Backup", new String("Created"));

            Intent Home = new Intent(getApplicationContext(), MainActivity.class);
            startActivity(Home);
        } else {
            warningTV.setText("You need to create at least "+minShares.toString()+" shares");
        }
    }


}

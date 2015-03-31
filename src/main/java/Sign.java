// Applet for signing PDF documents.
// By ID Solutions ApS, based on the Digital Signature Services project. License: LGPL 2.1
//
// Applet parameters:
//      service_url: server running the demo applet remoting service
//
// Most of the user interface is done in JavaScript. The following JS functions must be available:
//      void appletReady(): Called when applet is starting, to let JS know it can start using it.
//
// JS should do the following:
//      call selectInputFile
//      call selectOutputFile
//      call selectNextCert
// Then, assuming these were sucessful, call signDocument and possibly upload.

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.common.PinInputDialog;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.pades.PAdESService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.MSCAPISignatureToken;
import eu.europa.ec.markt.dss.signature.token.Pkcs11SignatureToken;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.tsp.OnlineTSPSource;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import netscape.javascript.JSObject;
import javax.swing.JApplet;
import javax.swing.GroupLayout.Alignment;
import javax.swing.GroupLayout;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.AbstractAction;
import java.awt.event.ActionEvent;
import javax.swing.Action;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

// Our pom.xml uses Maven's assembly plugin to get dependencies included: stackoverflow.com/questions/574594
//
// If plexus-archiver reports a stack overflow when building, set environment option: MAVEN_OPTS=-Xss16m
//
// To avoid mixed-code warnings, see stackoverflow.com/questions/19393826. Basically, it can't work with all versions of Java

public class Sign extends JApplet {
	public Sign() {
	}

    // To keep track of our progress in loading certs from different APIs:
    private List<DSSPrivateKeyEntry> keys;
    private int nextkeyidx;
    private String currentApi = "";     // One of "CAPI", "MOCCA" or "PKCS#11"

    // These vars correspond to parts of the demo applet's model:
    private File fileToSign = null;     // model: selectedFile
    private SignatureTokenConnection signingToken = null;
    private DSSPrivateKeyEntry privateKey = null;  // model: selectedPrivateKey
    private String targetFileName = "";

    // User interface (in addition to the auto-genereated at the end of the file):
    private PinInputDialog pinInputDlg;
    
    public void init() {
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Sign.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Sign.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Sign.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Sign.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }

        // Prepare our UI
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable() {
                public void run() {
                    initComponents();
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        pinInputDlg = new PinInputDialog(this);
    }

    @Override
    public void start() {
        // Invoke javascript to tell we're ready.
        // TODO: just remove this, Java 7 has a built-in mechanism: docs.oracle.com/javase/tutorial/deployment/applet/appletStatus.html
        JSObject window = JSObject.getWindow(this);
        window.eval("appletReady();");
    }

    //  Ask user to select the PDF file to be signed.
    //  The result is stored, and the file name without path returned.
    //  If no file was selected, we keep and return any previously selected file. If none, return "".
    public String selectInputFile() {
        //  We re-elevate our priviledges, see docs.oracle.com/javase/7/docs/api/java/security/AccessController.html
        return AccessController.doPrivileged(
                new PrivilegedAction<String>() {
            public String run() {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter pdfFilter = new FileNameExtensionFilter("Document PDF", "pdf");
                chooser.setFileFilter(pdfFilter);
                if (chooser.showOpenDialog(jLabel1) == JFileChooser.APPROVE_OPTION) {
                    fileToSign = chooser.getSelectedFile();
                }
                if (fileToSign != null) {
                    return fileToSign.getAbsolutePath();
                } else {
                    return "";
                }
            }
        });
    }

    // Filename to write signed file to when signing.  An existing file will then be overwritten.
    public String selectOutputFile() {
        // Just take the input file, remove the extension, and add -signed.pdf.
        targetFileName = fileToSign.getAbsolutePath().substring(0, fileToSign.getAbsolutePath().length() - 4)
                         + "-signed.pdf";
        return targetFileName;
    }

    // Try the available APIs until we get a certificate, then store that and return its distinguished name.
    // Repeat the call to search for another cert. Returns "" if no more certs were found.
    // When signing, we'll use the last cert returned from here.
    public String selectNextCert(boolean restart) {
        if (restart || keys == null) {
            keys = new ArrayList<DSSPrivateKeyEntry>();
            nextkeyidx = 0;
            currentApi = "";
        }
        //  We re-elevate our priviledges, see docs.oracle.com/javase/7/docs/api/java/security/AccessController.html
        return AccessController.doPrivileged(
                new PrivilegedAction<String>() {
            public String run() {
                privateKey = nextCert();        // Note that signingToken is set to match privateKey
                
                if (privateKey != null) {
                    return privateKey.getCertificate().getSubjectDN().getName() + " (" + currentApi + ")";
                } else {
                    return "";
                }
            }
        });
    }

    // Perform the signing set up using the above methods.  Return "" if OK, otherwise error message.
    // If this is the last/only document to sign, close the connection. (We never close on error, to allow for retries).
    // The return code indicates success.
    public boolean signDocument(final boolean closeConnectionOnSuccess) {
        //  We re-elevate our priviledges, see docs.oracle.com/javase/7/docs/api/java/security/AccessController.html
        return AccessController.doPrivileged(
                new PrivilegedAction<Boolean>() {
            public Boolean run() {
                try {
                    signDocumentPriv();
                    if (closeConnectionOnSuccess)
                        signingToken.close();
                    return true;
                } catch (DSSException ex) {
                    displayError("Impossible de signer le document avec " + currentApi + " (DSS error).", ex);
                } catch (Throwable ex) {
                    displayError("mpossible de signer le document avec " + currentApi + ".", ex);
                }
                return false;
            }
        });
    }

    // Upload the signed file to this url, using POST to the specified form.
    // Also, the form will post the full pathname as parameter "path".
    // The return code indicates success.
    public boolean upload(final String serverUrl, final String formname)
    {
        //  We re-elevate our priviledges, see docs.oracle.com/javase/7/docs/api/java/security/AccessController.html
        return AccessController.doPrivileged(
                new PrivilegedAction<Boolean>() {
            public Boolean run() {
                try {
                    postToServer(serverUrl, formname);
                    return true;
                } catch (MalformedURLException ex) {
                    displayError("Error when uploading signed file to server (wrong URL).", ex);
                } catch (IOException ex) {
                    displayError("Error when uploading signed file to server.", ex);
                }
                return false;
            }
        });
    }
    
    private void displayError(String msg, Throwable ex)
    {
        if (ex.getMessage() != null)
            msg += "\n\nError message:\n" + ex.getMessage();
        JOptionPane.showMessageDialog(jLabel1, msg);
        Logger.getLogger(Sign.class.getName()).log(Level.INFO, null, ex);
    }
    
    // Post the signed file to the server with HTTP or HTTPS
    // Consider: only allow to post to our own URL
    private void postToServer(String ServerUrl, String FormName) throws MalformedURLException, IOException {
        URL url = new URL(ServerUrl);
        File f = new File(targetFileName);
        
        // Assumably, this uses the proxy set in the Java control panel, which defaults to browser's settings.
        // So no need to worry about proxy.

        // Also, we don't test for SSL certificate issues, because our host is expected to be the same as the
        // page hosting this applet, so the browser has already checked (though quickly changing DNS might fool us).
        
        // This automatically sends the browser's cookies, unless they are marked HttpOnly (.Net tends to do that).
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setDoOutput(true);     // Output = extra data in http request (post data)
        conn.setRequestMethod("POST");
        conn.setReadTimeout(300000); // 5 minutes
        // The post syntax is described here: http://www.w3.org/TR/html401/interact/forms.html#h-17.13.4.2
        // Good guide: http://stackoverflow.com/questions/2793150/how-to-use-java-net-urlconnection-to-fire-and-handle-http-requests/2793153#2793153
        conn.setRequestProperty("Content-Type", "multipart/form-data;boundary=**!!**");
        DataOutputStream request = new DataOutputStream(conn.getOutputStream());
        
        // Send the full path as a normal param
        request.writeBytes("--**!!**\r\n");     // two dashes, boundary, crlf
        request.writeBytes("Content-Disposition: form-data; name=\"path\"\r\n");
        request.writeBytes("Content-Type: text/plain; charset=UTF-8\r\n");
        request.writeBytes("\r\n");
        // filename may contain all kinds of strange chars, but only quotes are both troublesome and likely.
        request.write(targetFileName.replace("\"", "_").getBytes("UTF-8"));
        request.writeBytes("\r\n");

        // Then the header for the actual file
        request.writeBytes("--**!!**\r\n");     // two dashes, boundary, crlf
        // According to RFC 2388, the filename should be RFC2231-encoded (MIME-encoding), but direct UTF-8 is what actually works.
        // https://www.w3.org/Bugs/Public/show_bug.cgi?id=16909
        request.writeBytes("Content-Disposition: form-data; name=\"" + FormName + "\"; filename=\"");
        request.write(f.getName().replace("\"", "_").getBytes("UTF-8"));    // again, remove quotes
        request.writeBytes("\"\r\n");
        request.writeBytes("Content-Type: application/pdf\r\n");        // Maybe guess content-type using file.probeContentType (java 7) or URLConnection.guessContentTypeFromName
        request.writeBytes("\r\n");
        // read the signed file contents from disk (well, we could have saved it in ram, but so what...)
        byte [] fileData = new byte[(int)f.length()];
        DataInputStream dis = new DataInputStream(new FileInputStream(f));
        dis.readFully(fileData);
        dis.close();
        request.write(fileData);

        request.writeBytes("\r\n");
        request.writeBytes("--**!!**--\r\n");   // boundary with dashes before and after
        request.close();
        
        if(!conn.getResponseMessage().equals("OK")) {
            throw new IOException(conn.getResponseMessage());
        }
     }
    
    // If we have untried certs left over in keys, get that, otherwise load some certs and try again.
    // Note that signingToken will always match the cert returned!
    private DSSPrivateKeyEntry nextCert() {
        if (nextkeyidx < keys.size()) {
            return keys.get(nextkeyidx++);
        } else {
            if (signingToken != null) {
                signingToken.close();
            }
            switch (currentApi) {
                case "":     // start from beginning
                    currentApi = "CAPI";
                    if (System.getProperty("os.name").startsWith("Windows")) {
                        signingToken = new MSCAPISignatureToken();
                        loadCerts();
                    }
                    return nextCert();
                case "CAPI":
                    currentApi = "PKCS#11";
                    JOptionPane.showMessageDialog(this,
                            "The software from the issuer of your certificate/key probably follows a standard called PKCS#11."
                            + "\n\nWe need to know the name and location of the file that contains the PKCS#11 program library."
                            + "\n\nIf you don't know, please ask your issuer.",
                            "Select PKCS#11 library", JOptionPane.INFORMATION_MESSAGE);
                    JFileChooser chooser = new JFileChooser();
                    if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                        signingToken = new Pkcs11SignatureToken(chooser.getSelectedFile().getAbsolutePath(), pinInputDlg, 0/*slot*/);
                        loadCerts();
                    }
                    return nextCert();
                case "PKCS#11":
                default:
                    return null;    // nothing left to try
            }
        }
    }

    // Add certs from the current signingToken to our list, if they are valid and trusted.
    private void loadCerts() {
        try {
            List<DSSPrivateKeyEntry> newkeys = signingToken.getKeys();
            for (DSSPrivateKeyEntry newkey : newkeys) {
                try {
                    boolean already = false;
                    for (DSSPrivateKeyEntry oldkey : keys) {
                        if (oldkey.getCertificate().getSubjectDN().getName().equals(newkey.getCertificate().getSubjectDN().getName())) {
                            already = true;
                        }
                    }
                    newkey.getCertificate().checkValidity();
                    if (!already) {
						keys.add(newkey);
					}
                } 
				catch (CertificateExpiredException ex) {
                    JOptionPane.showMessageDialog(jLabel1, "Ce certificat n'est plus valide:\n"
                            + newkey.getCertificate().getSubjectDN().getName()
                            + "\n\nNous allons essayer de trouver un autre certificat.");
                }
				catch (CertificateNotYetValidException ex) {
                    JOptionPane.showMessageDialog(jLabel1, "Ce certificat n'est pas encore valide:\n"
                            + newkey.getCertificate().getSubjectDN().getName()
                            + "\n\nNous allons essayer de trouver un autre certificat.");
                }
            }
        } 
		catch (Throwable ex)
		{
            Logger.getLogger(Sign.class.getName()).log(Level.INFO, null, ex);
        }
    }
    
    // Adapted from CookBook v 2.2 pg 48.
    private void signDocumentPriv() {
        DSSDocument toSignDocument = new FileDocument(fileToSign);

        SignatureParameters parameters = new SignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED); // signature part of PDF
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setPrivateKeyEntry(privateKey);

        // For LT-level signatures, we would need a TrustedListCertificateVerifier, but for level T,
        // a CommonCertificateVerifier is enough. (CookBook v 2.2 pg 28)
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        PAdESService service = new PAdESService(commonCertificateVerifier);
        
        // For now, just hard-code one specific time stamp server (the same as DSS demo app uses by default)
        OnlineTSPSource tspSource = new OnlineTSPSource("http://tsa.belgium.be/connect");
        service.setTspSource(tspSource);

        byte[] dataToSign = service.getDataToSign(toSignDocument, parameters);
	DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
	byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);

	DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
        signedDocument.save(targetFileName);
    }

    //@SuppressWarnings("unchecked")
    private void initComponents() {

        //Etiquette
    	jLabel1 = new javax.swing.JLabel();
        jLabel1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/logocpas.png"))); // NOI18N
        jLabel1.setText("CPAS Namur");

        //Bouton signer
        jButton1 = new javax.swing.JButton();
        jButton1.addMouseListener(new MouseAdapter() {
        	@Override
        	public void mouseClicked(MouseEvent arg0) {
        		selectInputFile();
        	}
        });
        jButton1.setText("Signer");
        jButton1.setToolTipText("Signer un fichier PDF");
        
        

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        layout.setHorizontalGroup(
        	layout.createParallelGroup(Alignment.LEADING)
        		.addGroup(layout.createSequentialGroup()
        			.addContainerGap()
        			.addGroup(layout.createParallelGroup(Alignment.TRAILING, false)
        				.addComponent(jButton1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        				.addComponent(jLabel1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 233, Short.MAX_VALUE))
        			.addContainerGap(207, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
        	layout.createParallelGroup(Alignment.LEADING)
        		.addGroup(layout.createSequentialGroup()
        			.addContainerGap()
        			.addComponent(jLabel1)
        			.addPreferredGap(ComponentPlacement.RELATED)
        			.addComponent(jButton1)
        			.addContainerGap(190, Short.MAX_VALUE))
        );
        getContentPane().setLayout(layout);
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JButton jButton1;
    private final Action action = new SwingAction();
    // End of variables declaration//GEN-END:variables
	private class SwingAction extends AbstractAction {
		public SwingAction() {
			putValue(NAME, "SwingAction");
			putValue(SHORT_DESCRIPTION, "Some short description");
		}
		public void actionPerformed(ActionEvent e) {
		}
	}
}

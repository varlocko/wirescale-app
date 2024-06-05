//////////////////////////////////////////////////////////////////////////////////////////////
//
// An implementation of the Teleport programming challenge
//
// See https://drive.google.com/file/d/13bh52wYy1YqTqy-pLGb92UUsE8koylX7/view for details.
//
// - Prompt for a username and password.
// - Authenticate with Keycloak.
// - Generate or provide a Wireguard public key.
// - Set up the Wireguard configuration on the user's computer.
//
// Copyright: none for now, TBD.
//
/////////////////////////////////////////////////////////////////////////////////////////////
package main


import (
   "bufio"
   "bytes"
   "crypto/rand"
   "encoding/base64"
   "fmt"
   "log"
   "os"
   "os/exec"


   "github.com/go-resty/resty/v2"
   "golang.org/x/crypto/curve25519"
)


///////////////////////////////
//                           //
// Keycloak conf parameters  //
//                           //
///////////////////////////////
const (
   KeycloakURL   = "https://url/auth/realms/realm/protocol/openid-connect/token"
   wireguardConf = "/etc/wireguard/wg0.conf"
   clientSecret  = "client-secret"
   clientID      = "client-id"
)


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// Prompt the user for their login and password                                                                      //
//  Returns: username and password                                                                                   //
//  Security issues: need to stricly validate input and return errors or re-prompt. Should also rate-limit attempts. //
//                   A good way to do this would be to wrap calls with this logic ultimately trapping an exception.  //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
func promptCreds() (string, string) {
   reader := bufio.NewReader(os.Stdin)
   fmt.Print("Enter your username: ")
   username, _ := reader.ReadString('\n')
   fmt.Print("Enter your password: ")
   password, _ := reader.ReadString('\n')
   return username[:len(username)-1], password[:len(password)-1]
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                    //
// Post to the Keycloak API based on the (eventually pre-validated) username and password and return an access token. //
//                                                                                                                    //
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
func authenticate(username, password string) (string, error) {
   client := resty.New()
   resp, err := client.R().
       SetFormData(map[string]string{
           "grant_type":    "password",
           "client_id":     clientID,
           "client_secret": clientSecret,
           "username":      username,
           "password":      password,
       }).
       Post(KeycloakURL)


   if err != nil {
       return "", err
   }


   var result map[string]interface{}
   if err := resp.Unmarshal(&result); err != nil {
       return "", err
   }


   token, ok := result["access_token"].(string)
   if !ok {
       return "", fmt.Errorf("failed to obtain access token")
   }


   return token, nil
}




///////////////////////////////////////////////////
//                                               //
// Generate a keypair to feed to Keycloak.       //
//                                               //
///////////////////////////////////////////////////
func generateKeyPair() (string, string, error) {
   var privateKey [32]byte
   _, err := rand.Read(privateKey[:])
   if err != nil {
       return "", "", err
   }


   var publicKey [32]byte
   curve25519.ScalarBaseMult(&publicKey, &privateKey)


   return base64.StdEncoding.EncodeToString(privateKey[:]), base64.StdEncoding.EncodeToString(publicKey[:]), nil
}


////////////////////////////////////////////////////////////////////
//                                                                //
// Security issues: need exception handling and perhaps logging.  //
// Future work: Universalize IPs                                  //
//                                                                //
////////////////////////////////////////////////////////////////////
func setupWireguard(publicKey string) error {
   cmd := exec.Command("wg", "set", "wg0", "peer", publicKey, "allowed-ips", "10.0.0.2/32")
   var out bytes.Buffer
   cmd.Stdout = &out
   err := cmd.Run()
   if err != nil {
       return fmt.Errorf("failed to set up Wireguard: %v", err)
   }
   fmt.Println(out.String())
   return nil
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                         //
// main() entry point for executable                                                                       //
// - Prompt for a username and password.                                                                   //
// - Authenticate with Keycloak.                                                                           //
// - Generate or provide a Wireguard public key.                                                           //
// - Set up the Wireguard configuration on the user's computer.                                            //
//                                                                                                         //
// Security issues: as documented above, need  some kind of global exception handling and perhaps logging. //
//                                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
func main() {
   username, password := promptCreds()


   token, err := authenticate(username, password)
   if err != nil {
       log.Fatalf("Authentication failed: %v", err)
   }
   fmt.Println("Authentication successful, token:", token)


   privateKey, publicKey, err := generateKeyPair()
   if err != nil {
       log.Fatalf("Key generation failed: %v", err)
   }
   fmt.Println("Wireguard Public Key:", publicKey)


   if err := setupWireguard(publicKey); err != nil {
       log.Fatalf("Wireguard setup failed: %v", err)
   }


   // Optionally save the private key securely
   fmt.Println("Wireguard setup complete. Save the private key securely.")
   fmt.Println("Wireguard Private Key:", privateKey)
}
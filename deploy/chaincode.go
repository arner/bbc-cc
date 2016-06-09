package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
)

//==============================================================================================================================
//	 Structure Definitions
//==============================================================================================================================
//	SimpleChaincode - A blank struct for use with Shim (An IBM Blockchain included go file used for get/put state
//					  and other IBM Blockchain functions)
//==============================================================================================================================
type SimpleChaincode struct {
}

type ECertResponse struct {
	OK string `json:"OK"`
}

type User struct {
	UserId       string   `json:"userId"` //Same username as on certificate in CA
	Salt         string   `json:"salt"`
	Hash         string   `json:"hash"`
	FirstName    string   `json:"firstName"`
	LastName     string   `json:"lastName"`
	Bikes       []string `json:"bikes"` //Array of bike IDs
	Address      string   `json:"address"`
	PhoneNumber  string   `json:"phoneNumber"`
	EmailAddress string   `json:"emailAddress"`
}

type Bike struct {
	BikeId     	string `json:"bikeId"`
	Owner 	    	string `json:"owner_id"`
	Status		string `json:"status"`
	Lock_id		string `json:"lock_id"`
	Brand		string `json:"brand"`
	Type		string `json:"type"`
	Yearofbuild	string `json:"yearofbuild"`
	Color		string `json:"color"`
	Comments	string `json:"comments"`
}

//=================================================================================================================================
//  Evaluation map - Equivalant to an enum for Golang
//  Example:
//  if(!SomeStatus[strings.ToUpper(status)]) { return nil, errors.New("Status not recognized") }
//=================================================================================================================================
var SomeStatus = map[string]bool{
	"somestatus": true,
}

//TODO:
//-- when used with bluemix, add parameter to assign api url for CA

//=================================================================================================================================
//  Index collections - In order to create new IDs dynamically and in progressive sorting
//  Example:
//    signaturesAsBytes, err := stub.GetState(signaturesIndexStr)
//    if err != nil { return nil, errors.New("Failed to get Signatures Index") }
//    fmt.Println("Signature index retrieved")
//
//    // Unmarshal the signatures index
//    var signaturesIndex []string
//    json.Unmarshal(signaturesAsBytes, &signaturesIndex)
//    fmt.Println("Signature index unmarshalled")
//
//    // Create new id for the signature
//    var newSignatureId string
//    newSignatureId = "sg" + strconv.Itoa(len(signaturesIndex) + 1)
//
//    // append the new signature to the index
//    signaturesIndex = append(signaturesIndex, newSignatureId)
//    jsonAsBytes, _ := json.Marshal(signaturesIndex)
//    err = stub.PutState(signaturesIndexStr, jsonAsBytes)
//    if err != nil { return nil, errors.New("Error storing new signaturesIndex into ledger") }
//=================================================================================================================================
var usersIndexStr = "_users"
var bikesIndexStr = "_bikes"

//==============================================================================================================================
//	Run - Called on chaincode invoke. Takes a function name passed and calls that function. Converts some
//		  initial arguments passed to other bikes for use in the called function e.g. name -> ecert
//==============================================================================================================================
func (t *SimpleChaincode) Run(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	fmt.Println("run is running " + function)
	return t.Invoke(stub, function, args)
}

func (t *SimpleChaincode) Invoke(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	fmt.Println("invoke is running " + function)

	if function == "init" {
		return t.Init(stub, "init", args)
	} else if function == "add_user" {
		return t.add_user(stub, args)
	} else if function == "add_bike" {
		return t.add_bike(stub, args)
	} else if function == "change_bike" {
		return t.change_bike(stub, args)
	} else if function == "mark_stolen" {
		return t.mark_stolen(stub, args)
	}

	return nil, errors.New("Received unknown invoke function name")
}

//=================================================================================================================================
//	Query - Called on chaincode query. Takes a function name passed and calls that function. Passes the
//  		initial arguments passed are passed on to the called function.
//
//  args[0] is the function name
//=================================================================================================================================
func (t *SimpleChaincode) Query(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {

	if args[0] == "get_user" {
		return t.get_user(stub, args[1])
	} else if args[0] == "get_bike" {
		return t.get_bike(stub, args)
	} else if args[0] == "get_all_bikes" {
		return t.get_all_bikes(stub, args)
	} else if args[0] == "authenticate" {
		return t.authenticate(stub, args)
	}

	return nil, errors.New("Received unknown query function name")
}

//=================================================================================================================================
//  Main - main - Starts up the chaincode
//=================================================================================================================================

func main() {
	err := shim.Start(new(SimpleChaincode))
	if err != nil {
		fmt.Printf("Error starting SimpleChaincode: %s", err)
	}
}

//==============================================================================================================================
//  Init Function - Called when the user deploys the chaincode
//==============================================================================================================================

func (t *SimpleChaincode) Init(stub *shim.ChaincodeStub, function string, args []string) ([]byte, error) {
	return nil, nil
}

//==============================================================================================================================
//  Utility Functions
//==============================================================================================================================

// "create":  true -> create new ID, false -> append the id
func append_id(stub *shim.ChaincodeStub, indexStr string, id string, create bool) ([]byte, error) {

	indexAsBytes, err := stub.GetState(indexStr)
	if err != nil {
		return nil, errors.New("Failed to get " + indexStr)
	}
	fmt.Println(indexStr + " retrieved")

	// Unmarshal the index
	var tmpIndex []string
	json.Unmarshal(indexAsBytes, &tmpIndex)
	fmt.Println(indexStr + " unmarshalled")

	// Create new id
	var newId = id
	if create {
		newId += strconv.Itoa(len(tmpIndex) + 1)
	}

	// append the new id to the index
	tmpIndex = append(tmpIndex, newId)
	jsonAsBytes, _ := json.Marshal(tmpIndex)
	err = stub.PutState(indexStr, jsonAsBytes)
	if err != nil {
		return nil, errors.New("Error storing new " + indexStr + " into ledger")
	}
	fmt.Println("Created new id.")
	fmt.Println(newId)
	return []byte(newId), nil
}

func calculate_hash(args []string) string {
	var str = ""
	for _, v := range args {
		str += v
	}
	hasher := md5.New()
	hasher.Write([]byte(str))
	return hex.EncodeToString(hasher.Sum(nil))
}

//==============================================================================================================================
//  Certificate Authentication
//==============================================================================================================================

func (t *SimpleChaincode) get_ecert(stub *shim.ChaincodeStub, name string) ([]byte, error) {

	var cert ECertResponse

	response, err := http.Get("http://localhost:5000/registrar/" + name + "/ecert") // Calls out to the HyperLedger REST API to get the ecert of the user with that name

	if err != nil {
		return nil, errors.New("Could not get ecert")
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body) // Read the response from the http callout into the variable contents

	if err != nil {
		return nil, errors.New("Could not read body")
	}

	err = json.Unmarshal(contents, &cert)

	if err != nil {
		return nil, errors.New("ECert not found for user: " + name)
	}

	return []byte(string(cert.OK)), nil
}

func (t *SimpleChaincode) get_cert_username(stub *shim.ChaincodeStub, encodedCert string) (string, error) {

	decodedCert, err := url.QueryUnescape(encodedCert) // make % etc normal //

	if err != nil {
		return "", errors.New("Could not decode certificate")
	}

	pem, _ := pem.Decode([]byte(decodedCert)) // Make Plain text   //

	x509Cert, err := x509.ParseCertificate(pem.Bytes)

	if err != nil {
		return "", errors.New("Couldn't parse certificate")
	}

	return x509Cert.Subject.CommonName, nil

}

func (t *SimpleChaincode) check_role(stub *shim.ChaincodeStub, encodedCert string) (int64, error) {
	ECertSubjectRole := asn1.ObjectIdentifier{2, 1, 3, 4, 5, 6, 7}

	decodedCert, err := url.QueryUnescape(encodedCert) // make % etc normal //

	if err != nil {
		return -1, errors.New("Could not decode certificate")
	}

	pem, _ := pem.Decode([]byte(decodedCert)) // Make Plain text   //

	x509Cert, err := x509.ParseCertificate(pem.Bytes) // Extract Certificate from argument //

	if err != nil {
		return -1, errors.New("Couldn't parse certificate")
	}

	var role int64
	for _, ext := range x509Cert.Extensions { // Get Role out of Certificate and return it //
		if reflect.DeepEqual(ext.Id, ECertSubjectRole) {
			role, err = strconv.ParseInt(string(ext.Value), 10, len(ext.Value)*8)

			if err != nil {
				return -1, errors.New("Failed parsing role: " + err.Error())
			}
			break
		}
	}

	return role, nil
}

//==============================================================================================================================
//  Invoke Functions
//==============================================================================================================================

func (t *SimpleChaincode) add_user(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	//Args
	//			0				1
	//		  index		user JSON object (as string)

	id, err := append_id(stub, usersIndexStr, args[0], false)
	if err != nil {
		return nil, errors.New("Error creating new id for user " + args[0])
	}

	err = stub.PutState(string(id), []byte(args[1]))
	if err != nil {
		return nil, errors.New("Error putting user data on ledger")
	}
	fmt.Println("Wrote user with id " + string(id) + " to the ledger.")
	return nil, nil
}

func (t *SimpleChaincode) add_bike(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	// args
	// 		0			1
	//	   index	   bike JSON object (as string)

	id, err := append_id(stub, bikesIndexStr, args[0], false)
	if err != nil {
		return nil, errors.New("Error creating new id for bike " + args[0])
	}

	var b Bike
	json.Unmarshal([]byte(args[1]), &b)
	b.BikeId = string(id)

	bstr, _ := json.Marshal(b)
	err = stub.PutState(b.BikeId, []byte(bstr))
	if err != nil {
		return nil, errors.New("Error putting bike data on ledger")
	} else {
		fmt.Println("Wrote bike with id " + b.BikeId + " to the ledger.")
	}

	// Add to user bikes

	if(len(b.Owner) > 0) {
		user, err := t.get_user(stub, b.Owner )
		if err != nil {
			return nil, errors.New("Error finding user in blockchain")
		}

		var u User
		json.Unmarshal(user, &u)

		//adding bike id to bikes from new owner
		u.Bikes = append(u.Bikes, string(id))
		nstr, _ := json.Marshal(u)
		err = stub.PutState(u.UserId, nstr)
		fmt.Println("Added bike with id " + b.BikeId + " to the bikes of user " + u.UserId)
	}

	return nil, nil
}

//function to change the owner of a bike
func (t *SimpleChaincode) change_bike(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	//Args
	//			1
	//		bikeID
	// getting bike with  correct id
	var strarr []string
	strarr[0] = args[0]

	bike, err := t.get_bike(stub, strarr)
	if err != nil {
		return nil, errors.New("Error finding bike in blockchain")
		}

	var b Bike
	json.Unmarshal(bike, &b)
	//change owner of bike to new owner (just in the bike)
	owner_old := b.Owner
	b.Owner = args[1]
	bstr, _ := json.Marshal(b)
	println("test " + b.Owner + b.BikeId + "asdf")
	//put changes in the blockchain
	err = stub.PutState(args[0], bstr)
	if err != nil {
		return nil, errors.New("Error putting bike data on ledger")
		}

	//getting old owner
	user, err := t.get_user(stub, owner_old )
	if err != nil {
		return nil, errors.New("Error finding user in blockchain")
		}

	var u User
	json.Unmarshal(user, &u)
	//removing bike id from bikes, old owner
	for i := 0; i < len(u.Bikes); i++  {
	//if bikes[i] is the same as the id found, delete it, and save it in the blockchain
	if u.Bikes[i] == b.BikeId {
		u.Bikes = append(u.Bikes[:i], u.Bikes[i + 1:]...)
		ustr, _ := json.Marshal(u)
		println("test " + u.UserId  + "asdf")
		err = stub.PutState(u.UserId, ustr)
		if err != nil {
			return nil, errors.New("Error removing bike from old user")
			}
		}
	}

	//retreiving new owner
	new_user, err := t.get_user(stub, args[1] )
	if err != nil {
		return nil, errors.New("Error finding user in blockchain")
		}
	var n User
	json.Unmarshal(new_user, &n)
	//adding bike id to bikes from new owner
	n.Bikes = append(n.Bikes, b.BikeId)
	nstr, _ := json.Marshal(n)
	// args
	// 		0			1
	//	   index	   bike JSON object (as string)
	println("test " + n.UserId  + "asdf")
	err = stub.PutState(n.UserId, nstr )
	if err != nil {
		return nil, errors.New("Error registering bike in the new ownerdata")
		}
	return nil, nil

};

func (t *SimpleChaincode) mark_stolen(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	fmt.Println(stub.GetCallerMetadata())
	fmt.Println(stub.GetCallerCertificate())
	fmt.Println(stub.CertAttributes())

	// TODO check user type

	bytes, err := stub.GetState(args[0])
	if err != nil {
		return nil, errors.New("Error getting bike from ledger")
	}

	var b Bike
	err = json.Unmarshal(bytes, &b)

	b.Status = "Marked stolen"

	nstr, _ := json.Marshal(b)
	err = stub.PutState(args[0], nstr)

	return []byte(nstr), err
}


//==============================================================================================================================
//		Query Functions
//==============================================================================================================================

func (t *SimpleChaincode) get_user(stub *shim.ChaincodeStub, userID string) ([]byte, error) {

	bytes, err := stub.GetState(userID)

	if err != nil {
		return nil, errors.New("Could not retrieve information for this user")
	}

	return bytes, nil

}

func (t *SimpleChaincode) get_bike(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	//Args
	//			1
	//		bikeID

	bytes, err := stub.GetState(args[1])

	if err != nil {
		return nil, errors.New("Error getting from ledger")
	}

	return bytes, nil

}

func (t *SimpleChaincode) get_all_bikes(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	var err error
	var bikes []Bike

	// TODO use secure context
	if (len(args) > 1 && len(args[1]) > 0 ) {
		bikes, err = t.GetUserBikes(stub, args[1])
	} else {
		bikes, err = t.GetAllBikes(stub)
	}
	if err != nil {
		return nil, errors.New("Could not get bikes")
	}

	bikesAsJsonBytes, err := json.Marshal(bikes)
	if err != nil {
		return nil, errors.New("Could not convert bikes to JSON ")
	}

	return bikesAsJsonBytes, nil
}


func (t *SimpleChaincode) authenticate(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	// Args
	//	1		2
	//	userId	password

	// TODO: get the certificate of the calling user. Is the calling user
	// sent correctly by IBC? (values below are empty)
	fmt.Println(stub.GetCallerMetadata())
	fmt.Println(stub.GetCallerCertificate())
	//fmt.Println(stub.CertAttributes())


	username := args[1]
	user, err := t.get_user(stub, username)
	// If user can not be found in ledgerstore, return authenticated false
	if err != nil {
		return []byte(`{ "authenticated": false, "certRole": -1  }`), nil
	}

	bikes, err := t.GetUserBikes(stub, username)
	if err != nil {
		return []byte(`{ "authenticated": false, "certRole": -1  }`), nil
	}

	bikesAsJsonBytes, _ := json.Marshal(bikes)
	str := `{ "authenticated": true, "certRole": 2,"user": ` + string(user) + `,"bikes":` + string(bikesAsJsonBytes) + `}`

	// validate passwords
	return []byte(str), nil
}


func (t *SimpleChaincode) GetUserBikes(stub *shim.ChaincodeStub, username string) ([]Bike, error) {
	user, err := t.get_user(stub, username)
	if err != nil {
		return nil, errors.New("Unable to get user with username: " + username)
	}
	var u User
	json.Unmarshal(user, &u)

	var bikes []Bike
	for _, bike := range u.Bikes {
		bytes, err := stub.GetState(bike)
		if err != nil {
			return nil, errors.New("Unable to get bike with ID: " + bike)
		}
		var b Bike
		json.Unmarshal(bytes, &b)
		fmt.Println("Retrieved bike with ID: " + b.BikeId)
		bikes = append(bikes, b)
	}
	return bikes, nil
}

func (t *SimpleChaincode) GetAllBikes(stub *shim.ChaincodeStub) ([]Bike, error) {
	indexAsBytes, err := stub.GetState(bikesIndexStr)
	if err != nil {
		return nil, errors.New("Failed to get " + bikesIndexStr)
	}
	fmt.Println(bikesIndexStr + " retrieved")
	fmt.Println(string(indexAsBytes[:]))

	// Unmarshal the index
	var bikesIndex []string
	err = json.Unmarshal(indexAsBytes, &bikesIndex)
	if err != nil {
		fmt.Println(err)
		return nil, errors.New("Failed to get " + bikesIndexStr)
	}

	var bikes []Bike
	for _, bike := range bikesIndex {

		bytes, err := stub.GetState(bike)
		if err != nil {
			return nil, errors.New("Unable to get bike with ID: " + bike)
		}

		var t Bike
		json.Unmarshal(bytes, &t)
		bikes = append(bikes, t)
	}

	return bikes, nil
}
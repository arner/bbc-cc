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
	"math"
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
	Bikes       []string  `json:"bikes"` //Array of bike IDs
	Address      string   `json:"address"`
	PhoneNumber  string   `json:"phoneNumber"`
	EmailAddress string   `json:"emailAddress"`
	Role         string   `json:"role"` // TODO: make enum (if json.marshal can handle it) if done, cases should be updated as well!!
}

type Bike struct {
	BikeId     	string `json:"bikeId"`
	FrameNumber   	string `json:"frame_number"`
	Owner 	    	string `json:"owner_id"`
	Status		string `json:"status"`
	LockId		string `json:"lock_id"`
	Brand		string `json:"brand"`
	Type		string `json:"type"`
	YearOfBuild	string `json:"yearofbuild"`
	Color		string `json:"color"`
	DefaultPrice	float64 `json:"defaultprice"`
	SellPrice	float64 `json:"sellprice"`
	InsuranceValue 	float64 `json:"insurancevalue"`
	Comments	string `json:"comments"`
	Insured		bool 	`json:"insured"`
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
	} else if function == "mark_stolen_accepted" {
		return t.mark_stolen_accepted(stub, args)
	} else if function == "insure" {
		return t.insure(stub, args)
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
	} else if args[0] == "get_all_users" {
		return t.get_all_users(stub)
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
	fmt.Println("Created new id " + newId);
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
	bikeAsJsonString := args[0]

	// TODO check userid/owner
	id, err := append_id(stub, bikesIndexStr, bikesIndexStr, true)
	if err != nil {
		return nil, errors.New("Error creating new id for bike " + string(bikeAsJsonString))
	}
	fmt.Println(bikeAsJsonString)
	var b Bike
	json.Unmarshal([]byte(bikeAsJsonString), &b)
	b.BikeId = string(id)
	if b.Status == "" {
		b.Status = "OK"
	}

	bikeAsByteArray, _ := json.Marshal(b)
	err = stub.PutState(b.BikeId, bikeAsByteArray)
	if err != nil {
		return nil, errors.New("Error putting bike data on ledger")
	} else {
		fmt.Println("Wrote bike with id " + b.BikeId + " to the ledger.")
		fmt.Println([]byte(bikeAsJsonString))
	}

	// Add to user bikes
	if(len(b.Owner) > 0) {
		u, err := t.GetUser(stub, b.Owner)
		if err != nil {
			return nil, errors.New("Error finding user in blockchain")
		}
		//adding bike id to bikes from new owner
		u.Bikes = append(u.Bikes, b.BikeId)
		nstr, _ := json.Marshal(u)
		err = stub.PutState(u.UserId, nstr)
		fmt.Println("Added bike with id " + b.BikeId + " to the bikes of user " + u.UserId)
	} //first user, could be fabric or bikeshop
	// else if {} bovenstaand gedeelte werkt niet helemaal volgens mij

	return nil, nil
}

//function to change the owner of a bike
func (t *SimpleChaincode) change_bike(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeId := args[0]
	newOwnerId := args[1]
	oldOwnerId := args[2]

	fmt.Println("Will transfer bike " + bikeId + " from " + oldOwnerId + " to " + newOwnerId)

	oldOwner, err := t.GetUser(stub, oldOwnerId)
	if err != nil {
		return nil, errors.New("Error finding old owner in blockchain")
	}
	newOwner, err := t.GetUser(stub, newOwnerId)
	if err != nil {
		return nil, errors.New("Error finding new owner in blockchain")
	}
	// getting bike with  correct id
	b, err := t.GetBike(stub, bikeId, oldOwner)
	if err != nil {
		return nil, errors.New("Error finding bike in blockchain")
	}

	// check if user is really the owner of the bike
	if oldOwnerId != b.Owner {
		return nil, errors.New("gebruiker is geen eigenaar van de fiets")
	}

	//change owner of bike to new owner (just in the bike)
	fmt.Println("oude gebruiker is " + oldOwnerId + " en komt overeen met "+ b.Owner)
	b.Owner = newOwnerId
	bstr, _ := json.Marshal(b)
	fmt.Println("nieuwe gebruiker " + b.Owner +" het id van de fiets "+ b.BikeId)
	//put changes in the blockchain
	err = stub.PutState(bikeId, bstr)
	if err != nil {
		return nil, errors.New("Error putting bike data on ledger")
	}

	//removing bike id from bikes, old owner
	for i := 0; i < len(oldOwner.Bikes); i++  {
	//if bikes[i] is the same as the id found, delete it, and save it in the blockchain
		if oldOwner.Bikes[i] == b.BikeId {
			oldOwner.Bikes = append(oldOwner.Bikes[:i], oldOwner.Bikes[i + 1:]...)
			ustr, _ := json.Marshal(oldOwner)
			fmt.Println("verwijderen van " + oldOwner.UserId  + " bij fiets " + b.BikeId + " is gelukt")
			err = stub.PutState(oldOwner.UserId, ustr)
			if err != nil {
				return nil, errors.New("Error removing bike from old user")
			}
		}
	}
	//TODO sell price should be given up. Default is no selling price
	if b.SellPrice != 0 && b.SellPrice < b.DefaultPrice && b.Insured {
		b.InsuranceValue = ((b.SellPrice + b.DefaultPrice)/2)
	} else if b.Insured {
		b.InsuranceValue = b.DefaultPrice
	}
	//round insurance value to 2 decimals
	if b.InsuranceValue > 0 {
		pow := math.Pow(10, float64(2))
		digit := pow * b.InsuranceValue
		round := math.Ceil(digit)
		b.InsuranceValue = round / pow
	}

	//adding bike id to bikes from new owner
	newOwner.Bikes = append(newOwner.Bikes, b.BikeId)
	nstr, _ := json.Marshal(newOwner)
	// args
	// 		0			1
	//	   index	   bike JSON object (as string)
	println("ophalen van gebruiker " + newOwner.UserId  + " is gelukt")
	err = stub.PutState(newOwner.UserId, nstr )
	if err != nil {
		return nil, errors.New("Error registering bike in the new ownerdata")
	}
	return nil, nil
};

func (t *SimpleChaincode) mark_stolen(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeid := args[0]
	userid := args[1]
	changedBike, err := t.ChangeStatus(stub, bikeid, userid, "Aangifte gedaan")
	fmt.Println(err)
	return changedBike, err
}

func (t *SimpleChaincode) mark_stolen_accepted(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeid := args[0]
	userid := args[1]
	changedBike, err := t.ChangeStatus(stub, bikeid, userid, "Aangifte bevestigd")
	fmt.Println(err)
	return changedBike, err
}

func (t *SimpleChaincode) mark_found(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeid := args[0]
	userid := args[1]
	changedBike, err := t.ChangeStatus(stub, bikeid, userid, "Fiets gevonden")
	fmt.Println(err)
	return changedBike, err
}

func (t *SimpleChaincode) mark_retreived(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeid := args[0]
	userid := args[1]
	changedBike, err := t.ChangeStatus(stub, bikeid, userid, "OK")
	fmt.Println(err)
	return changedBike, err
}

func (t *SimpleChaincode) ChangeStatus(stub *shim.ChaincodeStub, bikeid, userid, status string) ([]byte, error) {
	// TODO validations, role, etc, --> done review needed
	fmt.Println("[ChangeStatus] " + bikeid + " will be " + status)
	u, err := t.GetUser(stub, userid)
	if err != nil {
		return nil, errors.New("Could not retrieve user from ledger")
	}
	b, err := t.GetBike(stub, bikeid, u)
	if err != nil {
		return nil, errors.New("Could not retrieve bike from ledger")
	}

	// TODO, kan mogelijk simpeler, voor overzichtelijkheid misschien in een aparte functie?. werkt niet
	// check states
	checksum := false
	allestatussen := []string{"Aangifte gedaan", "Aangifte bevestigd", "Fiets gevonden", "OK"}
	for _, v := range allestatussen {
		if v == status {
			checksum = true
		}
	}
	if !checksum {
		return nil, errors.New("status bestaat niet")
	}

	// switch to determin preconditions, and validate input/role
	switch u.Role {
	case "":
		return nil, errors.New("user has no role")
	case "1":
		if b.Owner != u.UserId || status == "Aangifte bevestigd" {
			return nil, errors.New("gebruiker is geen eigenaar")
		}
	case "2":
		if b.Status != "Aangifte gedaan" && b.Status != "Aangifte bevestigd" && b.Status != "Fiets gevonden" {
			return nil, errors.New("Fiets niet gestolen, wijzigen moet gebeuren vanuit de gebruiker")
		}
	default:
		return nil, errors.New("undefined role, or no rights to change the status")
	}
	b.Status = status

	bikeAsByteArray, _ := json.Marshal(b)
	err = stub.PutState(bikeid, bikeAsByteArray)

	fmt.Println("Marked " + bikeid + " as stolen")
	return bikeAsByteArray, err
}


func (t *SimpleChaincode) insure(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	bikeid := args[0]
	userid := args[1]

	user, err := t.GetUser(stub, userid)
	bike, err := t.GetBike(stub, bikeid, user)
	if err != nil {
		return nil, errors.New("Could not retrieve bike from ledger")
	}

	// validation: review needed
	if (user.Role != "1") || (user.UserId != bike.Owner) {
		return nil, errors.New("User has no rights of insuring the bike, or is not a owner of this bike")
	}
	//checksum to see if user exists in frauderegister
	checksum := true
	frauderegister := []string{"xxxxx8e2a67b4f7", "OK"}
	for _, v := range frauderegister {
		if v == user.UserId {
			checksum = false
			fmt.Println(user.FirstName + " staat in het frauderegister")
		}
	}
	if !checksum {
		return nil, errors.New("Gebruiker staat in het frauderegister en zal geen verzekering kunnen afsluiten")
	}
	//check if the insurance value should be chaged because of cheap selling
	if bike.SellPrice != 0 && bike.SellPrice < bike.DefaultPrice {
		bike.InsuranceValue = ((bike.SellPrice + bike.DefaultPrice)/2)
	} else {
		bike.InsuranceValue = bike.DefaultPrice
	}
	//Rounding the insurancevalue to 2 decimals.
	if bike.InsuranceValue > 0{
	pow := math.Pow(10, float64(2))
	digit := pow * bike.InsuranceValue
	round := math.Ceil(digit)
	bike.InsuranceValue = round / pow
	}

	bike.Insured = true

	bikeAsByteArray, _ := json.Marshal(bike)
	err = stub.PutState(bikeid, bikeAsByteArray)

	fmt.Println("Insured " + bikeid + ".")
	return bikeAsByteArray, err
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
	//1		bikeID
	//2		UserID

	//get user
	usr, err := stub.GetState(args[2])
	var u User
	json.Unmarshal(usr, &u)
	if err != nil {
		return nil, errors.New("Error getting user from ledger")
	}
	//get bike
	bytes, err := stub.GetState(args[1])
	var b Bike
	json.Unmarshal(bytes, &b)
	if err != nil {
		return nil, errors.New("Error getting bike from ledger")
	}
	return bytes, nil
}

func (t *SimpleChaincode) get_all_bikes(stub *shim.ChaincodeStub, args []string) ([]byte, error) {
	username := args[1]

	u, err := t.GetUser(stub, username)
	bikes, err := t.GetAllBikes(stub, u)

	if err != nil {
		return nil, errors.New("Could not get bikes")
	}

	bikesAsJsonBytes, err := json.Marshal(bikes)
	if err != nil {
		return nil, errors.New("Could not convert bikes to JSON ")
	}

	return bikesAsJsonBytes, nil
}


// Get user and check password. We don't use the Certificate yet.
func (t *SimpleChaincode) authenticate(stub *shim.ChaincodeStub, args []string) ([]byte, error) {

	username := args[1]
	//password := args[2]

	user, err := t.GetUser(stub, username)
	if err != nil { /*|| user.Password != password*/
		return []byte(`{ "authenticated": false, "certRole": -1  }`), err
	}

	userAsJsonBytes, _ := json.Marshal(user)
	str := `{ "authenticated": true, "certRole": 2,"user": ` + string(userAsJsonBytes) + `}`

	return []byte(str), nil
}

func (t *SimpleChaincode) GetUser(stub *shim.ChaincodeStub, username string) (User, error) {
	var u User

	userbytes, err := t.get_user(stub, username)
	if err != nil {
		return u, errors.New("Unable to get user with username: " + username)
	}
	err = json.Unmarshal(userbytes, &u)

	return u, err
}


func(t *SimpleChaincode) get_all_users(stub *shim.ChaincodeStub) ([]byte, error){
	//svar userlist []User
	var userlistid []string
	var userlist []User
	fmt.Println("hier komt hij wel")
	userbytes, err := stub.GetState(usersIndexStr)
	err = json.Unmarshal(userbytes, &userlistid)
	for _, userid := range userlistid {
		user, err := t.GetUser(stub, userid)
		if err == nil {
			userlist = append(userlist, user)
		}
	}
	returnlist, err := json.Marshal(userlist)
	if err != nil {
		return returnlist, errors.New("Unable to get users ")
	}
	return returnlist, err
}



func (t *SimpleChaincode) GetBike(stub *shim.ChaincodeStub, bikeid string, u User) (Bike, error) {
	fmt.Println("[GetBike] Retrieving bike: " + bikeid + " from owner " + u.UserId)
	var b Bike
	bytes, err := stub.GetState(bikeid)
	if err != nil {
		return b, errors.New("Unable to get bike with ID: " + bikeid)
	}
	err = json.Unmarshal(bytes, &b)

	//create switch, check role. if role is 1, its a normal user
	fmt.Println("User with id " + u.UserId + " has role " + u.Role)
	switch u.Role {
	case "":
		return b, errors.New("user has no role")
	case "1":
		if b.Owner != u.UserId {
			return b, errors.New("gebruiker is geen eigenaar")
		}

	case "2":
		if b.Status != "Aangifte gedaan" && b.Status != "Aangifte bevestigd" {
			return b, errors.New("Fiets niet gestolen")
		}
	case "3":
		if !b.Insured {
			return b, errors.New("fiets niet verzekerd")
		}
	default:
		return b, errors.New("undefined role")
	}
	//moddify results by role TODO werkt, meer onderscheid maken?
	if u.Role == "2" {
		b.DefaultPrice = 0
	}
	if u.Role == "3"{

		b.BikeId 	= "Not Visible"
		b.FrameNumber 	= "Not Visible"
		b.LockId  	= "Not Visible"
		b.Brand  	= "Not Visible"
		b.Type 		= "Not Visible"
		b.YearOfBuild 	= "Not Visible"
		b.Color 	= "Not Visible"
		b.Comments 	= "Not Visible"

	}

	return b, err
}

// Returns bikes. If user type = 1 only user bikes, else all bikes
func (t *SimpleChaincode) GetAllBikes(stub *shim.ChaincodeStub, u User) ([]Bike, error) {
	var bikesIndex []string
	var bikes []Bike
	var err error

	if u.Role == "1" {
		bikesIndex = u.Bikes
	} else {
		bikesIndex, err = t.GetAllBikeIds(stub) // will this return nil or an empty array?
	}

	if bikesIndex == nil {
		return bikes, err
	}

	for _, bikeid := range bikesIndex {
		bike, err := t.GetBike(stub, bikeid, u)

		// TODO: disable certain fields based on role --> moved this to the getbike function
		if err == nil {
			bikes = append(bikes, bike)
		}
	}

	return bikes, nil
}

func (t *SimpleChaincode) GetAllBikeIds(stub *shim.ChaincodeStub) ([]string, error) {
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
	return bikesIndex, err
}

package main

import "fmt"
import L "./certs"
func main(){
    fmt.Println("sss")
    L.GenerateCerts("172:22:43:55,10:73:34:22", "aa")
}
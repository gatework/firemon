// Package yamlfile reads the operator inventory from a YAML file: which
// firewalls exist, which HA cluster and snapshot each belongs to, and which
// networks each protects behind which zone. It is the local implementation
// of the protected-network source; a production deployment can provide
// the same data from a database instead.
//
//	firewalls:
//	  - name: SZX9-FW01
//	    cluster: SZX9-FW
//	    snapshot: SZX9-FW01
//	    protected:
//	      - zone: INSIDE
//	        networks: [10.250.0.0/16]
//	        exclude: [10.250.255.0/24]
package yamlfile

// Package inventory answers questions across several firewalls: which
// firewalls a flow crosses, how each one treats it, and what each one must
// change to permit it.
//
// A firewall is crossed by the part of a request that it routes in through
// one interface and out through another, provided it owns an end of that
// traffic. Ownership is longest-prefix across the inventory: the firewalls
// whose route to the sources (or destinations) is the most specific of all
// firewalls own them — several sites routing 10.0.0.0/8 inward do not own a
// host behind the one site that routes its /16. Default routes own nothing,
// so Internet destinations are owned by no firewall and the source owner
// alone decides. HA pairs with the same routes own the same ends. From the
// source owners the trace follows route next hops: a next hop that is an
// interface address of another firewall puts that firewall on the path
// too, which finds transit firewalls such as an Internet edge.
//
// Firewalls whose zones cannot be derived from routing (transparent,
// layer-2 deployments) are not located automatically.
package inventory

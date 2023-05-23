/*
Package bincmd provides commands for managing binary objects.

The client must provide the connection info provider to create
a new instance of the bin command:

	f := func() (conn.Info, error) {
		...
	}
	...
	bincmd.Cmd(f)

Main subcommands:

  - add
  - get
  - list
  - update
  - delete

Workflow of the command:

 1. entering authentication data
 2. creating a new connection session with the server
 3. executing a subcommand: add, get, delete, list, update
 4. session termination.

Adding new subcommands:

	root.AddCommand(
		addCmd(),
		deleteCmd(),
		getCmd(),
		indexCmd(),
		updateCmd(),
		...
	)
*/
package bincmd

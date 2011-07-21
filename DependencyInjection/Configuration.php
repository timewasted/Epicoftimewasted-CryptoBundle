<?php

namespace Epicoftimewasted\CryptoBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
	/**
	 * Generates the configuration tree.
	 *
	 * @return TreeBuilder
	 */
	public function getConfigTreeBuilder()
	{
		$treeBuilder = new TreeBuilder();
		$rootNode = $treeBuilder->root('epicoftimewasted_crypto');

		$rootNode
			->addDefaultsIfNotSet()
			->children()
				->scalarNode('algorithm')->defaultValue('sha512')->end()
			->end();

		return $treeBuilder;
	}
}

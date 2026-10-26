"""Curated, easy-to-spell words for memorable passphrase generation."""

from __future__ import annotations

# Short, concrete English words. Duplicates are removed once at import and the
# generator uses the resulting count to report conservative entropy.
WORDS: tuple[str, ...] = tuple(
    dict.fromkeys(
        """
        acorn alder almond amber anchor antler apple apricot april aqua archer
        arctic arrow ash aspen asteroid atlas aurora autumn avocado azure badger
        bamboo banjo barley basil beacon berry birch biscuit bison blend bloom
        bluff bolt border boulder breeze brick bridge bright bronze brook brush
        bubble bucket buffalo bugle butter cabin cactus camel candle candy canoe
        canvas canyon carbon cargo carpet castle cedar chalk charm cherry chess
        chief cinnamon circle citrus clover cobalt coconut comet copper coral
        cotton cougar cove crane crater crimson crystal cube daisy dawn delta
        denim desert dew diamond dolphin donut dragon drift drum dune dusk eagle
        earth echo eclipse ember emerald falcon feather fern ferry fiddle field
        finch fire fjord flame flint flower flute fog forest fossil fox frost
        galaxy garden garnet gecko ginger glacier glade glass globe glove gold
        goose granite grape grass gravel green grove guitar harbor hare harvest
        hawk hazel heather heron hill honey horizon horse island ivory jackal
        jade jaguar jasmine jazz jelly jewel juniper kayak kettle kiwi koala
        lagoon lake lamp lantern lark laurel lava leaf lemon lily lime linen lion
        lizard lobster lotus lunar lynx magnet mango maple marble marsh meadow
        melon mesa meteor mint mirror mist mole monarch moon moose moss mountain
        mouse mule mushroom nectar nickel night north nutmeg oak oasis ocean
        olive onyx opal orbit orchard osprey otter owl oyster palm panda paper
        parrot peach pearl pebble pecan pelican pepper petal piano pine planet
        plum pocket polar pond poppy prairie prism puffin pumpkin quartz quill
        quince rabbit raven reef ribbon rice ridge river robin rocket rose ruby
        saddle sage salmon sand sapphire satin scarlet seal shadow shell shore
        silver sky slate sloth smoke snow solar sparrow spice spring spruce
        squash star steel stone storm stream sugar summit sun sunset swan sweet
        swift sycamore table tangerine teal thistle thunder tide tiger timber
        topaz torch toucan tower trail tulip tundra turtle twilight umber valley
        vanilla velvet violet vista walnut wave whale wheat willow wind winter
        wolf wren yarrow yellow zebra zenith zephyr zinc
        """
        .split()
    )
)
